#!/usr/bin/env bash
# Scan the CVEs that ship inside the AEP Streaming Connect connector artifacts
# (shaded uber jar + Confluent archive zip). See agents/skills/cve-scan-and-fix.md (repo root) for usage.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scan-jar.sh [options] [ARTIFACT ...]

Artifact source (pick one; default is --build):
  -b, --build            Build the current checkout and scan the shaded jar + Confluent zip
  ARTIFACT ...           Scan the given .jar / .zip files or directories

Options:
  -s, --scopes           Cross-check against Gradle's runtimeClasspath (build mode only)
  -o, --out DIR          Output directory (default: build/jar-cve-scan/<label>)
      --skip-db-update   Do not refresh the Trivy/Grype vulnerability databases
  -h, --help             Show this help
EOF
}

MODE="" SCOPES=0 OUT="" DB_UPDATE=1
ARTIFACTS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--build) MODE=build ;;
    -s|--scopes) SCOPES=1 ;;
    -o|--out) OUT="$2"; shift ;;
    --skip-db-update) DB_UPDATE=0 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    *) ARTIFACTS+=("$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"); MODE=files ;;
  esac
  shift
done
MODE="${MODE:-build}"

log() { printf '\n==> %s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

need=(trivy grype syft python3 unzip)
for t in "${need[@]}"; do
  command -v "$t" >/dev/null || die "'$t' not found on PATH. Install it (see Prerequisites in agents/skills/cve-scan-and-fix.md)"
done
[[ $SCOPES == 1 && $MODE != build ]] && die "--scopes only works with --build (it reads the current checkout's Gradle graph)"

case "$MODE" in
  build)   LABEL="build-$(git -C "$ROOT" rev-parse --short HEAD)" ;;
  files)   LABEL="files-$(date +%Y%m%d-%H%M%S)" ;;
esac
# Build first: `gradlew clean` wipes build/, which is where the output goes by default.
if [[ $MODE == build ]]; then
  log "Building shaded jar and Confluent zip (tests and checkstyle skipped)"
  (cd "$ROOT" && ./gradlew clean build kafkaConnectPublish -x test -x checkstyleMain -x checkstyleTest -q)
  shopt -s nullglob
  ARTIFACTS=("$ROOT"/streaming-connect-sink/build/libs/streaming-connect-sink-*-java-*.jar
             "$ROOT"/build/distributions/*.zip)
  shopt -u nullglob
fi

OUT="${OUT:-$ROOT/build/jar-cve-scan/$LABEL}"
rm -rf "$OUT" && mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
RAW="$OUT/raw" STAGE="$OUT/stage"
mkdir -p "$RAW" "$STAGE"

{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "mode: $MODE"
  echo "git: $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo n/a)"
  echo "trivy: $(trivy --version 2>/dev/null | head -1)"
  echo "grype: $(grype version 2>/dev/null | awk '/^Version/{print $2}')"
  echo "syft: $(syft version 2>/dev/null | awk '/^Version/{print $2}')"
} > "$RAW/env.txt"

if [[ $DB_UPDATE == 1 ]]; then
  log "Updating vulnerability databases"
  trivy image --download-db-only --quiet || die "trivy DB update failed (network?). Re-run, or use --skip-db-update."
  trivy image --download-java-db-only --quiet || die "trivy Java DB update failed. Re-run, or use --skip-db-update."
  grype db update >/dev/null || die "grype DB update failed. Re-run, or use --skip-db-update."
fi

[[ ${#ARTIFACTS[@]} -gt 0 ]] || die "no artifacts to scan"

for a in "${ARTIFACTS[@]}"; do
  [[ -e $a ]] || die "artifact not found: $a"
  name="$(basename "$a")"; name="${name%.*}"
  dir="$STAGE/$name"; mkdir -p "$dir"
  case "$a" in
    *.zip) unzip -q "$a" -d "$dir" ;;
    *)     if [[ -d $a ]]; then cp -R "$a"/. "$dir"/; else cp "$a" "$dir"/; fi ;;
  esac
  log "Scanning $name"
  trivy rootfs --quiet --skip-db-update --skip-java-db-update --scanners vuln -f json -o "$RAW/trivy-$name.json" "$dir"
  syft scan "dir:$dir" -q -o "cyclonedx-json=$RAW/sbom-$name.cdx.json"
  grype "sbom:$RAW/sbom-$name.cdx.json" -q -o json --file "$RAW/grype-$name.json"
done

DECLARED_ARGS=()
if [[ $SCOPES == 1 ]]; then
  log "Cross-check: scanning Gradle runtimeClasspath (what the build declares it bundles)"
  (cd "$ROOT" && ./gradlew -q :streaming-connect-sink:dependencies --configuration runtimeClasspath) > "$RAW/gradle-runtimeClasspath.txt"
  python3 "$SCRIPT_DIR/jar_cve_report.py" deps-to-sbom "$RAW/gradle-runtimeClasspath.txt" "$RAW/sbom-declared.cdx.json"
  trivy sbom --quiet --skip-db-update --skip-java-db-update --scanners vuln -f json -o "$RAW/declared-trivy.json" "$RAW/sbom-declared.cdx.json"
  grype "sbom:$RAW/sbom-declared.cdx.json" -q -o json --file "$RAW/declared-grype.json"
  DECLARED_ARGS=(--declared "$RAW/gradle-runtimeClasspath.txt")
fi

log "Building report"
python3 "$SCRIPT_DIR/jar_cve_report.py" report --raw "$RAW" --out "$OUT" --label "$LABEL" ${DECLARED_ARGS[@]+"${DECLARED_ARGS[@]}"}
rm -rf "$STAGE"
echo
echo "Report:   $OUT/JAR-CVE-REPORT.md"
echo "CSV:      $OUT/findings.csv"
echo "Raw data: $RAW"
