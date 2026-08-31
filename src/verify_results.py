"""
verify_results.py — check that the shipped result tables match the shipped raw results.

The earlier version of this script compared the manuscript against `rq4_results.json`.
The manuscript is not part of this repository, so the check is now self-contained: it
regenerates the tables from the raw experiment output and compares them against the
committed copy in `results/`. If the two ever diverge, something in `results/` has been
edited by hand and the package can no longer be trusted.

    python src/verify_results.py

Exits non-zero on any mismatch.
"""
from __future__ import annotations
import json, os, sys, subprocess, tempfile, filecmp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(ROOT, "results")
RESULTS = os.path.join(RESULTS_DIR, "rq4_results.json")
MANIFEST = os.path.join(RESULTS_DIR, "rq4_manifest.json")
COMMITTED_TABLES = os.path.join(RESULTS_DIR, "rq4_tables_check.txt")
GENERATOR = os.path.join(ROOT, "src", "make_rq4_tables.py")

TOOLS = ["checkov", "tfsec", "terrascan", "trivy"]


def check_tables_match_results() -> bool:
    """Regenerate the tables into a temp dir and diff against the committed copy."""
    with tempfile.TemporaryDirectory() as tmp:
        r = subprocess.run([sys.executable, GENERATOR, RESULTS, tmp],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("[!] table generator failed:")
            print(r.stderr[:600])
            return False
        regenerated = os.path.join(tmp, "rq4_tables_check.txt")
        if not os.path.exists(regenerated):
            print("[!] generator produced no rq4_tables_check.txt")
            return False
        if not os.path.exists(COMMITTED_TABLES):
            print("[!] results/rq4_tables_check.txt is missing")
            return False
        same = filecmp.cmp(regenerated, COMMITTED_TABLES, shallow=False)
        if not same:
            print("[!] committed tables differ from the ones regenerated from the results:")
            a = open(COMMITTED_TABLES).read().splitlines()
            b = open(regenerated).read().splitlines()
            for i, (x, y) in enumerate(zip(a, b)):
                if x != y:
                    print(f"    line {i+1}\n      committed:   {x}\n      regenerated: {y}")
        return same


def check_verdict_vocabulary(results) -> bool:
    """Every verdict must be one of the declared values, and none may be silently blank."""
    allowed = {"RESOLVED", "NOT_RESOLVED", "INCONCLUSIVE", "ERROR", "N/A", "PARTIAL"}
    ok = True
    counts = {}
    for prop in results:
        for tool in results[prop]:
            for construct, rec in results[prop][tool].items():
                v = rec.get("verdict")
                counts[v] = counts.get(v, 0) + 1
                if v not in allowed:
                    print(f"[!] unexpected verdict {v!r} at {prop}/{tool}/{construct}")
                    ok = False
    print("  verdict counts:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if counts.get("ERROR"):
        print("  note: ERROR verdicts present; these are execution failures, not blind spots")
    return ok


def check_raw_runs(manifest) -> bool:
    raw_dir = os.path.join(RESULTS_DIR, "raw_runs")
    if not os.path.isdir(raw_dir):
        print("[!] results/raw_runs/ is missing")
        return False
    files = [f for f in os.listdir(raw_dir) if f.endswith(".json")]
    claimed = manifest.get("total_tool_runs")
    print(f"  raw run records: {len(files)} (manifest claims {claimed})")
    if claimed is not None and len(files) != claimed:
        print("[!] record count does not match the manifest")
        return False
    bad = 0
    for f in files:
        try:
            rec = json.load(open(os.path.join(raw_dir, f)))
        except Exception as e:
            print(f"[!] {f} is not valid JSON: {e}")
            bad += 1
            continue
        for field in ("cmd", "returncode", "stdout", "stderr"):
            if field not in rec:
                print(f"[!] {f} is missing '{field}'")
                bad += 1
                break
    return bad == 0


def main() -> int:
    for p in (RESULTS, MANIFEST):
        if not os.path.exists(p):
            print(f"[!] missing {p}")
            return 2

    results = json.load(open(RESULTS))
    manifest = json.load(open(MANIFEST))

    print("=== provenance ===")
    for k, v in (manifest.get("tool_versions") or {}).items():
        print(f"  {k:11s} {v}")
    print(f"  terraform init executed: {manifest.get('terraform_init_executed')}")
    print(f"  properties reported:     {', '.join(manifest.get('properties', []))}")
    for k, v in (manifest.get("excluded_properties") or {}).items():
        print(f"  excluded:                {k} ({v[:60]}...)")

    print("\n=== verdicts ===")
    ok_vocab = check_verdict_vocabulary(results)

    print("\n=== raw execution records ===")
    ok_raw = check_raw_runs(manifest)

    print("\n=== tables vs results ===")
    ok_tables = check_tables_match_results()
    if ok_tables:
        print("  committed tables regenerate exactly from rq4_results.json")

    print("\n" + "=" * 62)
    if ok_vocab and ok_raw and ok_tables:
        print("PASS - results, tables and execution records are internally consistent.")
        return 0
    print("FAIL - see the messages above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
