#!/usr/bin/env python3
"""Turn Trivy + Grype scans of shipped connector artifacts into one CVE report.

Subcommands:
  deps-to-sbom <gradle-dependencies.txt> <out.cdx.json>
      Convert `gradle dependencies --configuration runtimeClasspath` output into a
      minimal CycloneDX SBOM so Trivy/Grype can scan the *declared* runtime graph.
  report --raw DIR --out DIR [--label L] [--declared gradle-dependencies.txt]
      Merge raw/trivy-<artifact>.json + raw/grype-<artifact>.json into
      findings.csv, summary.json and JAR-CVE-REPORT.md.
"""
import argparse
import csv
import glob
import json
import os
import re
from collections import Counter, defaultdict

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NEGLIGIBLE": 4, "UNKNOWN": 5}
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
GAV_RE = re.compile(r"[+\\]--- ([\w.\-]+):([\w.\-]+)(?::([\w.\-]+))?(?: -> ([\w.\-]+))?(.*)$")


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4])


def parse_gradle_deps(path):
    """Return {group:artifact: version} from `gradle dependencies` tree output."""
    deps = {}
    for line in open(path):
        m = GAV_RE.search(line)
        if not m:
            continue
        g, a, v, resolved, tail = m.groups()
        if "(c)" in tail or "(n)" in tail or a.endswith("-bom"):
            continue
        version = resolved or v
        if version:
            deps[f"{g}:{a}"] = version
    return deps


def deps_to_sbom(src, dst):
    deps = parse_gradle_deps(src)
    comps = []
    for ga, v in sorted(deps.items()):
        g, a = ga.split(":")
        purl = f"pkg:maven/{g}/{a}@{v}"
        comps.append({"type": "library", "bom-ref": purl, "group": g, "name": a, "version": v, "purl": purl})
    with open(dst, "w") as fh:
        json.dump({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": comps}, fh, indent=1)
    print(f"declared runtime dependencies: {len(comps)}")


def purl_to_name(purl, fallback):
    m = re.match(r"pkg:maven/([^/]+)/([^@]+)@", purl or "")
    return f"{m.group(1)}:{m.group(2)}" if m else fallback


def short_loc(path):
    if not path:
        return ""
    path = re.sub(r"^.*/stage/[^/]+/", "", path)
    return path.split(":")[0].lstrip("/")


class Findings:
    def __init__(self):
        self.items = {}

    def add(self, artifact, vid, aliases, pkg, ver, sev, fixed, title, loc, tool, cvss):
        cve = next((a for a in [vid, *aliases] if a and a.startswith("CVE-")), vid)
        f = self.items.setdefault((cve, pkg, ver), {
            "id": cve, "aliases": set(), "package": pkg, "version": ver, "severity": "UNKNOWN",
            "fixed": set(), "title": "", "cvss": None, "tools": set(), "artifacts": set(), "locations": set()})
        f["aliases"].update(a for a in [vid, *aliases] if a and a != cve)
        if SEV_ORDER.get(sev, 5) < SEV_ORDER.get(f["severity"], 5):
            f["severity"] = sev
        f["fixed"].update(x.strip() for x in fixed if x and x.strip())
        if title and not f["title"]:
            f["title"] = " ".join(title.split())
        if cvss and (f["cvss"] is None or cvss > f["cvss"]):
            f["cvss"] = cvss
        f["tools"].add(tool)
        f["artifacts"].add(artifact)
        if loc:
            f["locations"].add(short_loc(loc))

    def ingest_trivy(self, path, artifact):
        data = json.load(open(path))
        for res in data.get("Results") or []:
            for v in res.get("Vulnerabilities") or []:
                pkg = purl_to_name((v.get("PkgIdentifier") or {}).get("PURL"), v.get("PkgName"))
                scores = [s.get("V3Score") or s.get("V40Score") for s in (v.get("CVSS") or {}).values()]
                scores = [s for s in scores if s]
                self.add(artifact, v["VulnerabilityID"], [], pkg, v.get("InstalledVersion"),
                         v.get("Severity", "UNKNOWN"), (v.get("FixedVersion") or "").split(","),
                         v.get("Title", ""), v.get("PkgPath") or res.get("Target"), "trivy",
                         max(scores) if scores else None)

    def ingest_grype(self, path, artifact):
        data = json.load(open(path))
        for m in data.get("matches") or []:
            vul, art = m["vulnerability"], m["artifact"]
            related = m.get("relatedVulnerabilities") or []
            pkg = purl_to_name(art.get("purl"), art.get("name"))
            cvss = max([c.get("metrics", {}).get("baseScore", 0) for c in vul.get("cvss") or []] or [0]) or None
            title = vul.get("description") or next((r.get("description") for r in related if r.get("description")), "")
            locs = [l.get("accessPath") or l.get("path") for l in art.get("locations") or []]
            self.add(artifact, vul["id"], [r["id"] for r in related], pkg, art.get("version"),
                     (vul.get("severity") or "UNKNOWN").upper(), (vul.get("fix") or {}).get("versions") or [],
                     title[:160], locs[0] if locs else None, "grype", cvss)

    def rows(self):
        return sorted(self.items.values(), key=lambda f: (SEV_ORDER.get(f["severity"], 5), -(f["cvss"] or 0),
                                                           f["package"], f["id"]))


def min_fix(installed, candidates):
    """Smallest fixed version on the installed major line, else smallest newer version."""
    iv = vtuple(installed)
    newer = sorted((c for c in candidates if vtuple(c) > iv), key=vtuple)
    same_major = [c for c in newer if vtuple(c)[:1] == iv[:1]]
    return (same_major or newer or [None])[0]


def package_targets(rows):
    pkgs = defaultdict(lambda: {"counts": Counter(), "fix": None, "nofix": [], "artifacts": set(), "worst": "UNKNOWN"})
    for f in rows:
        p = pkgs[(f["package"], f["version"])]
        p["counts"][f["severity"]] += 1
        p["artifacts"] |= f["artifacts"]
        if SEV_ORDER.get(f["severity"], 5) < SEV_ORDER.get(p["worst"], 5):
            p["worst"] = f["severity"]
        fix = min_fix(f["version"], f["fixed"])
        if fix is None:
            p["nofix"].append(f["id"])
        elif p["fix"] is None or vtuple(fix) > vtuple(p["fix"]):
            p["fix"] = fix
    return sorted(pkgs.items(), key=lambda kv: (SEV_ORDER.get(kv[1]["worst"], 5), -sum(kv[1]["counts"].values())))


def md_escape(s):
    return (s or "").replace("|", "/").replace("\n", " ")


def report(args):
    raw, out = args.raw, args.out
    shipped = Findings()
    artifacts = []
    for path in sorted(glob.glob(os.path.join(raw, "trivy-*.json"))):
        name = os.path.basename(path)[len("trivy-"):-len(".json")]
        artifacts.append(name)
        shipped.ingest_trivy(path, name)
        gpath = os.path.join(raw, f"grype-{name}.json")
        if os.path.exists(gpath):
            shipped.ingest_grype(gpath, name)
    if not artifacts:
        raise SystemExit(f"no trivy-*.json files in {raw}")
    rows = shipped.rows()

    declared_rows, declared_deps = None, {}
    if args.declared:
        declared_deps = parse_gradle_deps(args.declared)
        declared = Findings()
        if os.path.exists(os.path.join(raw, "declared-trivy.json")):
            declared.ingest_trivy(os.path.join(raw, "declared-trivy.json"), "declared")
        if os.path.exists(os.path.join(raw, "declared-grype.json")):
            declared.ingest_grype(os.path.join(raw, "declared-grype.json"), "declared")
        declared_rows = declared.rows()

    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "findings.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "cvss", "id", "aliases", "package", "version", "fixed", "found_by", "artifacts",
                    "location", "title"])
        for f in rows:
            w.writerow([f["severity"], f["cvss"] or "", f["id"], " ".join(sorted(f["aliases"])), f["package"],
                        f["version"], ", ".join(sorted(f["fixed"], key=vtuple)), "+".join(sorted(f["tools"])),
                        " ".join(sorted(f["artifacts"])), "; ".join(sorted(f["locations"]))[:200], f["title"]])

    sev_total = Counter(f["severity"] for f in rows)
    per_artifact = {a: Counter(f["severity"] for f in rows if a in f["artifacts"]) for a in artifacts}
    targets = package_targets(rows)
    with open(os.path.join(out, "summary.json"), "w") as fh:
        json.dump({"label": args.label, "unique_cves": len(rows), "by_severity": dict(sev_total),
                   "by_artifact": {a: dict(c) for a, c in per_artifact.items()},
                   "packages": [{"package": k[0], "version": k[1], "worst": v["worst"], "counts": dict(v["counts"]),
                                 "minimum_fix": v["fix"], "no_fix": v["nofix"], "artifacts": sorted(v["artifacts"])}
                                for k, v in targets]}, fh, indent=1)

    env = open(os.path.join(raw, "env.txt")).read().strip() if os.path.exists(os.path.join(raw, "env.txt")) else ""
    L = []
    L.append(f"# Shipped-jar CVE report: {args.label}\n")
    L.append("Scope: third-party libraries **bundled inside the connector artifacts** (shaded jar / Confluent zip). "
             "The Kafka Connect worker, JRE, OS, test and build dependencies are out of scope.\n")
    if env:
        L.append("```\n" + env + "\n```\n")
    L.append("## Summary\n")
    L.append(f"**{len(rows)} unique CVEs**: " + ", ".join(f"{sev_total.get(s, 0)} {s.lower()}" for s in SEVS) + "\n")
    L.append("| Artifact | Critical | High | Medium | Low |\n|---|---|---|---|---|")
    for a in artifacts:
        c = per_artifact[a]
        L.append(f"| `{a}` | " + " | ".join(str(c.get(s, 0)) for s in SEVS) + " |")
    L.append("")
    L.append("## Fix targets (per library)\n")
    L.append("Minimum fix is the lowest version on the same major line that fixes every CVE listed for that "
             "library (falls back to the next major if there is no same-major fix).\n")
    L.append("| Library | Version | Critical | High | Medium | Low | Minimum fix | No fix available |\n"
             "|---|---|---|---|---|---|---|---|")
    for (pkg, ver), v in targets:
        L.append(f"| {pkg} | {ver} | " + " | ".join(str(v['counts'].get(s, 0)) for s in SEVS) +
                 f" | {v['fix'] or '-'} | {', '.join(v['nofix']) or '-'} |")
    L.append("")
    L.append("## All CVEs\n")
    L.append("| # | Severity | CVSS | CVE | Library | Version | Fixed in | Found by | Title |\n"
             "|---|---|---|---|---|---|---|---|---|")
    for i, f in enumerate(rows, 1):
        L.append(f"| {i} | {f['severity']} | {f['cvss'] or ''} | {f['id']} | {f['package']} | {f['version']} | "
                 f"{md_escape(', '.join(sorted(f['fixed'], key=vtuple)))} | {'+'.join(sorted(f['tools']))} | "
                 f"{md_escape(f['title'])[:110]} |")
    L.append("")

    if declared_rows is not None:
        L.append("## Cross-check against Gradle runtimeClasspath\n")
        art_keys = {(f["id"], f["package"], f["version"]) for f in rows}
        dec_keys = {(f["id"], f["package"], f["version"]) for f in declared_rows}
        only_declared = [f for f in declared_rows if (f["id"], f["package"], f["version"]) not in art_keys]
        only_artifact = [f for f in rows if (f["id"], f["package"], f["version"]) not in dec_keys]
        not_declared = sorted({f["package"] for f in rows if f["package"] not in declared_deps})
        L.append(f"- Declared runtime dependencies: {len(declared_deps)}; CVEs on declared graph: {len(declared_rows)}; "
                 f"CVEs in built artifacts: {len(rows)}.")
        if not only_declared and not only_artifact:
            L.append("- **Match**: the built artifacts and the declared runtime graph have exactly the same CVEs.")
        for f in only_declared:
            L.append(f"- Declared but not detected in artifact (check shading / exclusions): "
                     f"{f['id']} {f['package']} {f['version']}")
        for f in only_artifact:
            L.append(f"- Detected in artifact but not on declared graph: {f['id']} {f['package']} {f['version']}")
        for p in not_declared:
            L.append(f"- Library in artifact but not in runtimeClasspath: {p}")
        L.append("")

    with open(os.path.join(out, "JAR-CVE-REPORT.md"), "w") as fh:
        fh.write("\n".join(L))
    print(f"unique CVEs: {len(rows)} " + str({s: sev_total.get(s, 0) for s in SEVS}))
    for a in artifacts:
        print(f"  {a}: " + str({s: per_artifact[a].get(s, 0) for s in SEVS}))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("deps-to-sbom")
    d.add_argument("src")
    d.add_argument("dst")
    r = sub.add_parser("report")
    r.add_argument("--raw", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--label", default="scan")
    r.add_argument("--declared")
    args = ap.parse_args()
    if args.cmd == "deps-to-sbom":
        deps_to_sbom(args.src, args.dst)
    else:
        report(args)


if __name__ == "__main__":
    main()
