"""
Recompute the RQ3 resource-type counts with the correct counting unit.

Why this exists
---------------
The full recount counted security-sensitive resources once per cross-file EDGE. If two
modules both depend on the same target module, that target's resources were counted
twice. The manuscript counts them once per unique TARGETED MODULE, which is the intended
measure: "resource types declared in modules targeted by a local dependency".

The two units differ by a factor of 1.4x to 3.2x depending on the type, so the earlier
output cannot simply be substituted into the manuscript. This script settles it by
reporting both, side by side, using the corrected classifier.

Output
------
    rq3_out/rq3_corrected.json   both counting units, plus the domain rollup
"""
import sqlite3, json, os, glob, re
from collections import defaultdict, Counter

OUT = "/content/rq3_out" if os.path.isdir("/content") else "./rq3_out"
os.makedirs(OUT, exist_ok=True)

_REGISTRY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+$")

SEC_DOMAIN = {
    "aws_iam_policy": "IAM", "aws_iam_policy_document": "IAM",
    "aws_iam_role": "IAM", "aws_iam_role_policy_attachment": "IAM",
    "aws_security_group": "Network", "aws_security_group_rule": "Network",
    "aws_s3_bucket": "Storage", "aws_db_instance": "Storage",
    "azurerm_storage_account": "Storage",
    "aws_kms_key": "Encryption",
}
SEC = set(SEC_DOMAIN)


def classify(source):
    """Corrected classifier: normalise the path separator, as Terraform does."""
    s = (source or "").strip()
    if not s:
        return "other"
    n = s.replace("\\", "/")
    if n.startswith("./"):
        return "local_subdir"
    if n.startswith("../"):
        return "local_traversal"
    if s.startswith(("git::", "github.com", "git@")) or ".git" in s:
        return "vcs_remote"
    if s.startswith(("http://", "https://")):
        return "http_remote"
    if s.startswith(("s3::", "gcs::", "oss::")):
        return "cloud_bucket"
    if _REGISTRY.match(s) and not s.startswith("."):
        return "registry"
    return "other"


CROSS_FILE = {"local_subdir", "local_traversal"}


def norm(p):
    p = (p or "").strip().replace("\\", "/").strip("/")
    return p[2:] if p.startswith("./") else p


def find_db():
    for p in ["/content/terrads/TerraDS.sqlite", "data/terrads/TerraDS.sqlite",
              "TerraDS.sqlite"]:
        if os.path.exists(p):
            return p
    h = glob.glob("/content/**/TerraDS.sqlite", recursive=True)
    return h[0] if h else None


def main():
    db = find_db()
    if not db:
        print("[!] TerraDS.sqlite not found.")
        return
    print("DB:", db)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row

    mods = con.execute("SELECT Id,RepositoryId,Path,ModuleCalls FROM Modules").fetchall()
    by_repo = defaultdict(list)
    for m in mods:
        by_repo[m["RepositoryId"]].append(m)

    # resources per module, restricted to the security-sensitive set
    mod_res = defaultdict(list)
    for r in con.execute("SELECT ModuleId,Type FROM Resources").fetchall():
        if r["Type"] in SEC:
            mod_res[r["ModuleId"]].append(r["Type"])
    con.close()

    targeted_modules = set()   # unique modules reached by a cross-file dependency
    per_edge = Counter()       # counts a target's resources once per incoming edge
    repos_hit = 0

    for repo_id, modlist in by_repo.items():
        index = {norm(m["Path"]): m["Id"] for m in modlist}
        hit = False
        for m in modlist:
            raw = m["ModuleCalls"]
            if not raw or raw in ("[]", ""):
                continue
            try:
                calls = json.loads(raw)
            except Exception:
                continue
            sd = norm(m["Path"])
            for call in calls:
                src = call.get("source", "")
                if classify(src) not in CROSS_FILE:
                    continue
                joined = os.path.normpath(
                    os.path.join(sd, src.replace("\\", "/"))).replace("\\", "/")
                tid = index.get(norm(joined))
                if not tid:
                    continue
                types = mod_res.get(tid)
                if not types:
                    continue
                hit = True
                targeted_modules.add(tid)
                for t in types:
                    per_edge[t] += 1
        if hit:
            repos_hit += 1

    # the manuscript's unit: once per unique targeted module
    per_module = Counter()
    for tid in targeted_modules:
        for t in mod_res.get(tid, []):
            per_module[t] += 1

    dom_module = Counter()
    for t, c in per_module.items():
        dom_module[SEC_DOMAIN[t]] += c
    total_module = sum(per_module.values())

    print("\n" + "=" * 78)
    print("RQ3 RESOURCE-TYPE COUNTS, BY COUNTING UNIT")
    print("=" * 78)
    print(f"{'resource type':36s} {'per module':>12s} {'per edge':>12s}")
    print("-" * 78)
    for t, c in per_module.most_common():
        print(f"{t:36s} {c:12,} {per_edge[t]:12,}")
    print("-" * 78)
    print(f"{'TOTAL':36s} {total_module:12,} {sum(per_edge.values()):12,}")

    print(f"\nunique targeted modules: {len(targeted_modules):,}")
    print(f"repositories with a cross-file dependency into a security-sensitive module: "
          f"{repos_hit:,}")

    print("\ncontrol-domain rollup (per module, the manuscript's unit):")
    for d, c in dom_module.most_common():
        print(f"  {d:14s} {c:8,}  ({100*c/total_module:.1f}%)")

    json.dump({"per_module": dict(per_module),
               "per_edge": dict(per_edge),
               "domain_rollup_per_module": dict(dom_module),
               "total_per_module": total_module,
               "unique_targeted_modules": len(targeted_modules),
               "repos_hit": repos_hit},
              open(os.path.join(OUT, "rq3_corrected.json"), "w"), indent=2)
    print(f"\nwritten to {OUT}/rq3_corrected.json")


if __name__ == "__main__":
    main()
