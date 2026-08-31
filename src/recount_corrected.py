"""
Recount with the corrected classifier, and diagnose the 99-edge discrepancy.

Background
----------
Two numbers in the manuscript disagreed:

    RQ2 taxonomy      local_traversal + local_subdir = 101,787 + 59,930 = 161,717
    Resolver section  total local cross-file edges                      = 161,618
                                                                   gap =      99

The suspected cause is that Terraform accepts Windows-style relative module sources
(".\\modules\\x"), which one classifier treated as local and the other did not. This
script does not assume that. It counts, on the real dataset, exactly how many edges each
rule would move, prints them, and only then reports corrected totals.

Outputs
-------
    recount_out/diagnosis.json      what caused the gap, with examples
    recount_out/rq1_rq3_summary.json  corrected RQ1-RQ3 aggregates
    recount_out/per_repo.csv        corrected per-repository dataset
    recount_out/resolver_audit.csv  200-edge audit sample
"""
import sqlite3, json, os, glob, re, csv, math
from collections import defaultdict, Counter

OUT = "/content/recount_out" if os.path.isdir("/content") else "./recount_out"
os.makedirs(OUT, exist_ok=True)


# ----------------------------------------------------------------------
# classifiers: the OLD one (under-counting) and the CORRECTED one
# ----------------------------------------------------------------------
_REGISTRY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+$")


def classify_old(source):
    """The version that produced per_repo.csv: POSIX separators only."""
    s = (source or "").strip()
    if not s:
        return "other"
    if s.startswith("./"):
        return "local_subdir"
    if s.startswith("../"):
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


def classify_fixed(source):
    """Corrected: normalise the path separator first, as Terraform does."""
    s = (source or "").strip()
    if not s:
        return "other"
    s_norm = s.replace("\\", "/")
    if s_norm.startswith("./"):
        return "local_subdir"
    if s_norm.startswith("../"):
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
SEC = {"aws_iam_policy", "aws_iam_policy_document", "aws_iam_role",
       "aws_iam_role_policy_attachment", "aws_security_group",
       "aws_security_group_rule", "aws_s3_bucket", "aws_db_instance",
       "azurerm_storage_account", "aws_kms_key"}


def norm_path(p):
    p = (p or "").strip().replace("\\", "/").strip("/")
    return p[2:] if p.startswith("./") else p


def find_db():
    for p in ["/content/terrads/TerraDS.sqlite", "data/terrads/TerraDS.sqlite",
              "TerraDS.sqlite"]:
        if os.path.exists(p):
            return p
    hits = glob.glob("/content/**/TerraDS.sqlite", recursive=True) + \
           glob.glob("**/TerraDS.sqlite", recursive=True)
    return hits[0] if hits else None


def main():
    db = find_db()
    if not db:
        print("[!] TerraDS.sqlite not found. Run the Explorer notebook first.")
        return
    print("DB:", db)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row

    mods = con.execute("SELECT Id,RepositoryId,Path,ModuleCalls FROM Modules").fetchall()
    by_repo = defaultdict(list)
    for m in mods:
        by_repo[m["RepositoryId"]].append(m)

    mod_sec = defaultdict(bool)
    for r in con.execute("SELECT ModuleId,Type FROM Resources").fetchall():
        if r["Type"] in SEC:
            mod_sec[r["ModuleId"]] = True

    repo_meta = {r["Id"]: r for r in con.execute(
        "SELECT Id,StarCount,ForkCount,SizeInKb FROM Repositories").fetchall()}

    # ------------------------------------------------------------------
    # pass 1: diagnose — which sources do the two classifiers disagree on?
    # ------------------------------------------------------------------
    disagree = Counter()
    examples = defaultdict(list)
    tax_old, tax_new = Counter(), Counter()

    for repo_id, modlist in by_repo.items():
        for m in modlist:
            raw = m["ModuleCalls"]
            if not raw or raw in ("[]", ""):
                continue
            try:
                calls = json.loads(raw)
            except Exception:
                continue
            for call in calls:
                src = call.get("source", "")
                a, b = classify_old(src), classify_fixed(src)
                tax_old[a] += 1
                tax_new[b] += 1
                if a != b:
                    key = f"{a} -> {b}"
                    disagree[key] += 1
                    if len(examples[key]) < 5:
                        examples[key].append(src)

    cf_old = sum(tax_old[c] for c in CROSS_FILE)
    cf_new = sum(tax_new[c] for c in CROSS_FILE)

    print("\n" + "=" * 70)
    print("DIAGNOSIS OF THE DISCREPANCY")
    print("=" * 70)
    print(f"  total classified dependencies : {sum(tax_old.values()):,}")
    print(f"  cross-file, old classifier    : {cf_old:,}")
    print(f"  cross-file, corrected         : {cf_new:,}")
    print(f"  difference                    : {cf_new - cf_old:,}")
    print("\n  reclassified sources:")
    if not disagree:
        print("    none — the two classifiers agree on every source in this dataset")
    for k, v in disagree.most_common():
        print(f"    {k:34s} {v:6,}")
        for e in examples[k]:
            print(f"        e.g. {e!r}")

    # ------------------------------------------------------------------
    # pass 2: recompute RQ1-RQ3 and the per-repo table with the fixed rule
    # ------------------------------------------------------------------
    rows = []
    repos_any_dep = repos_cf = repos_sec = 0
    reached_types = Counter()
    resolved = unresolved = 0
    unresolved_reason = Counter()
    audit = []

    for repo_id, modlist in by_repo.items():
        index = {norm_path(m["Path"]): m["Id"] for m in modlist}
        n_mod = len(modlist)
        total_edges = cf_edges = 0
        cf_targets = set()
        for m in modlist:
            raw = m["ModuleCalls"]
            if not raw or raw in ("[]", ""):
                continue
            try:
                calls = json.loads(raw)
            except Exception:
                continue
            sd = norm_path(m["Path"])
            for call in calls:
                src = call.get("source", "")
                total_edges += 1
                if classify_fixed(src) not in CROSS_FILE:
                    continue
                cf_edges += 1
                joined = os.path.normpath(
                    os.path.join(sd, src.replace("\\", "/"))).replace("\\", "/")
                tgt = norm_path(joined)
                if tgt in index:
                    resolved += 1
                    cf_targets.add(index[tgt])
                else:
                    unresolved += 1
                    unresolved_reason[
                        "parent_traversal_escapes_repo" if tgt.startswith("..")
                        else "target_dir_not_indexed"] += 1
                if len(audit) < 200:
                    audit.append({"src_dir": sd, "source": src, "target": tgt,
                                  "resolved": tgt in index})
        if total_edges:
            repos_any_dep += 1
        if cf_edges:
            repos_cf += 1
        sec_hit = False
        for t in cf_targets:
            if mod_sec.get(t):
                sec_hit = True
        if sec_hit:
            repos_sec += 1
        meta = repo_meta.get(repo_id)
        rows.append({"repo_id": repo_id, "n_modules": n_mod,
                     "total_edges": total_edges, "cf_edges": cf_edges,
                     "has_cf": int(cf_edges > 0), "sec_reached": int(sec_hit),
                     "stars": (meta["StarCount"] if meta else 0) or 0,
                     "forks": (meta["ForkCount"] if meta else 0) or 0,
                     "size_kb": (meta["SizeInKb"] if meta else 0) or 0})

    # security-sensitive types reached
    for repo_id, modlist in by_repo.items():
        index = {norm_path(m["Path"]): m["Id"] for m in modlist}
        for m in modlist:
            raw = m["ModuleCalls"]
            if not raw or raw in ("[]", ""):
                continue
            try:
                calls = json.loads(raw)
            except Exception:
                continue
            sd = norm_path(m["Path"])
            for call in calls:
                src = call.get("source", "")
                if classify_fixed(src) not in CROSS_FILE:
                    continue
                joined = os.path.normpath(
                    os.path.join(sd, src.replace("\\", "/"))).replace("\\", "/")
                tid = index.get(norm_path(joined))
                if tid:
                    for r in con.execute(
                            "SELECT Type FROM Resources WHERE ModuleId=?", (tid,)):
                        if r["Type"] in SEC:
                            reached_types[r["Type"]] += 1
    con.close()

    total_repos = len(by_repo)
    cf_total = sum(tax_new[c] for c in CROSS_FILE)
    all_deps = sum(tax_new.values())

    print("\n" + "=" * 70)
    print("CORRECTED RESULTS")
    print("=" * 70)
    print(f"  repositories analysed              : {total_repos:,}")
    print(f"  ... with >=1 module dependency     : {repos_any_dep:,} ({100*repos_any_dep/total_repos:.1f}%)")
    print(f"  ... with >=1 cross-file dependency : {repos_cf:,} ({100*repos_cf/total_repos:.1f}%)")
    print(f"  ... targeting a security-sensitive module: {repos_sec:,} "
          f"({100*repos_sec/max(repos_cf,1):.1f}% of cross-file repos)")
    print(f"\n  total classified dependencies      : {all_deps:,}")
    print("  taxonomy:")
    for k, v in tax_new.most_common():
        print(f"    {k:18s} {v:8,}  ({100*v/all_deps:.1f}%)")
    print(f"\n  cross-file total                   : {cf_total:,} ({100*cf_total/all_deps:.1f}%)")
    print(f"  resolved to an in-repo module      : {resolved:,} ({100*resolved/max(cf_total,1):.1f}%)")
    print(f"  unresolved                         : {unresolved:,} ({100*unresolved/max(cf_total,1):.1f}%)")
    for k, v in unresolved_reason.most_common():
        print(f"    {k:32s} {v:6,} ({100*v/max(unresolved,1):.1f}% of unresolved)")
    print(f"\n  consistency check: resolved + unresolved = {resolved+unresolved:,} "
          f"(cross-file total {cf_total:,}) "
          f"{'MATCH' if resolved+unresolved==cf_total else 'MISMATCH'}")

    print("\n  security-sensitive types reached (top 10):")
    for k, v in reached_types.most_common(10):
        print(f"    {k:34s} {v:7,}")

    # ------------------------------------------------------------------
    # persist
    # ------------------------------------------------------------------
    json.dump({"gap_cause": dict(disagree),
               "gap_examples": {k: v for k, v in examples.items()},
               "cross_file_old": cf_old, "cross_file_corrected": cf_new,
               "difference": cf_new - cf_old},
              open(os.path.join(OUT, "diagnosis.json"), "w"), indent=2)
    json.dump({"RQ1": {"repos_total": total_repos,
                       "repos_any_dependency": repos_any_dep,
                       "repos_with_cf": repos_cf},
               "RQ2": dict(tax_new),
               "RQ3": {"repos_hit": repos_sec, "repos_cf": repos_cf,
                       "reached_types": dict(reached_types)},
               "resolver": {"cross_file_total": cf_total, "resolved": resolved,
                            "unresolved": unresolved,
                            "unresolved_reasons": dict(unresolved_reason)}},
              open(os.path.join(OUT, "rq1_rq3_summary.json"), "w"), indent=2)
    with open(os.path.join(OUT, "per_repo.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    with open(os.path.join(OUT, "resolver_audit.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["src_dir", "source", "target", "resolved"])
        w.writeheader(); w.writerows(audit)
    print(f"\nwritten to {OUT}/: diagnosis.json, rq1_rq3_summary.json, "
          f"per_repo.csv ({len(rows):,} rows), resolver_audit.csv")


if __name__ == "__main__":
    main()
