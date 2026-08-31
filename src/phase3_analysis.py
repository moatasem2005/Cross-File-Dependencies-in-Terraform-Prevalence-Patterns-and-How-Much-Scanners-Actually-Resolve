"""
Phase 3 — Cross-file / cross-module dependency analysis over TerraDS.
Builds a per-repository module dependency graph from the ModuleCalls metadata,
then answers RQ1 (prevalence), RQ2 (pattern taxonomy), RQ3 (security linkage).

Tested locally on a mock DB mirroring the confirmed TerraDS schema:
  Repositories(Id, FullName, StarCount, ForkCount, Archived, SizeInKb, Topics, License, ...)
  Modules(Id, RepositoryId, Path, Providers, ModuleCalls, DiagnosticMessages)
  Resources(Id, ModuleId, ResourceType, Name, Type, Provider)
"""

# --- canonical shared logic (single source of truth) ---
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from core import (classify_source as _classify_source, is_cross_file as _is_cross_file,
                  resolve_local_module as _resolve_local_module,
                  normalise_module_path as _normalise_module_path,
                  SECURITY_SENSITIVE_RESOURCES as _SEC)




SEC = _SEC
classify = _classify_source
classify_source = _classify_source
is_cf = _is_cross_file

import sqlite3, json, os, re, glob
from collections import Counter, defaultdict
import statistics as st

# ---------------------------------------------------------------- locate DB
def find_db():
    for p in ["data/terrads/TerraDS.sqlite", "/content/terrads/TerraDS.sqlite", "data/TerraDS.sqlite"]:
        if os.path.exists(p): return p
    hits = glob.glob("/content/**/TerraDS.sqlite", recursive=True) + glob.glob("**/TerraDS.sqlite", recursive=True)
    return hits[0] if hits else None

# ---------------------------------------------------------------- classify a module source
def classify_source(src: str) -> str:
    """Taxonomy of a Terraform module 'source' (RQ2)."""
    s = src.strip()
    if s.startswith("./") or s.startswith(".\\"):
        return "local_subdir"          # ./modules/x  — same-repo, downward
    if s.startswith("../"):
        return "local_traversal"       # ../modules/x — same-repo, crosses directories (cross-file)
    if s.startswith(("git::", "github.com", "git@")) or ".git" in s:
        return "vcs_remote"            # external git dependency
    if s.startswith(("http://", "https://")):
        return "http_remote"
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+$", s) and "registry" not in s and not s.startswith("."):
        return "registry"             # namespace/name/provider — Terraform Registry
    if s.startswith(("s3::", "gcs::", "oss::")):
        return "cloud_bucket"
    return "other"

def is_cross_file(kind: str) -> bool:
    """Which dependency kinds represent a CROSS-FILE / cross-directory link inside the repo."""
    return kind in ("local_subdir", "local_traversal")

# ---------------------------------------------------------------- load & build graphs
def load(db):
    con = sqlite3.connect(db); con.row_factory = sqlite3.Row
    return con

def build_repo_graphs(con):
    """For each repo: nodes = modules (by Path), edges = ModuleCalls resolved to intra-repo
    modules where possible. Returns dict repo_id -> {modules, edges, calls_by_kind}."""
    mods = con.execute("SELECT Id, RepositoryId, Path, Providers, ModuleCalls FROM Modules").fetchall()
    by_repo = defaultdict(list)
    for m in mods:
        by_repo[m["RepositoryId"]].append(m)

    graphs = {}
    for repo_id, modlist in by_repo.items():
        # index modules by normalized path for intra-repo resolution
        path_index = {}
        for m in modlist:
            p = (m["Path"] or "").strip("/").replace("\\", "/")
            path_index[p] = m["Id"]
        edges = []
        calls_by_kind = Counter()
        for m in modlist:
            raw = m["ModuleCalls"]
            if not raw or raw in ("[]", ""):
                continue
            try:
                calls = json.loads(raw)
            except Exception:
                continue
            src_dir = (m["Path"] or "").strip("/").replace("\\", "/")
            for call in calls:
                src = call.get("source", "")
                kind = classify_source(src)
                calls_by_kind[kind] += 1
                # try to resolve a local source to an actual module in the same repo
                resolved_id = None
                if kind in ("local_subdir", "local_traversal"):
                    # source is relative to the CALLER module's directory
                    joined = os.path.normpath(os.path.join(src_dir, src)).replace("\\", "/")
                    # normpath may yield a leading "./" or "" for repo root; normalize safely
                    target = joined[2:] if joined.startswith("./") else joined
                    target = target.strip("/")
                    resolved_id = path_index.get(target)
                edges.append({
                    "src_module": m["Id"], "target_name": call.get("name"),
                    "source": src, "kind": kind, "cross_file": is_cross_file(kind),
                    "resolved_target": resolved_id,
                })
        graphs[repo_id] = {"modules": modlist, "edges": edges, "calls_by_kind": calls_by_kind}
    return graphs

# ---------------------------------------------------------------- RQ1 prevalence
def rq1_prevalence(graphs):
    n_repos = len(graphs)
    repos_with_dep = sum(1 for g in graphs.values() if g["edges"])
    repos_with_crossfile = sum(1 for g in graphs.values()
                               if any(e["cross_file"] for e in g["edges"]))
    mod_counts = [len(g["modules"]) for g in graphs.values()]
    edge_counts = [len(g["edges"]) for g in graphs.values()]
    cf_edge_counts = [sum(1 for e in g["edges"] if e["cross_file"]) for g in graphs.values()]

    print("="*64); print("RQ1 — PREVALENCE"); print("="*64)
    print(f"repositories analysed: {n_repos}")
    print(f"  with >=1 module dependency: {repos_with_dep} ({100*repos_with_dep/n_repos:.1f}%)")
    print(f"  with >=1 CROSS-FILE dependency: {repos_with_crossfile} ({100*repos_with_crossfile/n_repos:.1f}%)")
    print(f"modules/repo: median={st.median(mod_counts)} mean={st.mean(mod_counts):.2f} max={max(mod_counts)}")
    print(f"dependency edges/repo: median={st.median(edge_counts)} mean={st.mean(edge_counts):.2f} max={max(edge_counts)}")
    print(f"cross-file edges/repo: median={st.median(cf_edge_counts)} mean={st.mean(cf_edge_counts):.2f} max={max(cf_edge_counts)}")
    return {"n_repos": n_repos, "repos_with_dep": repos_with_dep,
            "repos_with_crossfile": repos_with_crossfile}

# ---------------------------------------------------------------- RQ2 pattern taxonomy
def rq2_patterns(graphs):
    kind_total = Counter()
    resolved = Counter(); unresolved = Counter()
    for g in graphs.values():
        for e in g["edges"]:
            kind_total[e["kind"]] += 1
            if e["cross_file"]:
                if e["resolved_target"]: resolved[e["kind"]] += 1
                else: unresolved[e["kind"]] += 1
    print("\n" + "="*64); print("RQ2 — DEPENDENCY PATTERN TAXONOMY"); print("="*64)
    total = sum(kind_total.values()) or 1
    for k, c in kind_total.most_common():
        print(f"  {k:16s} {c:8d}  ({100*c/total:.1f}%)")
    print(f"\n  cross-file edges resolved to an intra-repo module: {sum(resolved.values())}")
    print(f"  cross-file edges NOT resolved (target module not in dataset): {sum(unresolved.values())}")
    return kind_total

# ---------------------------------------------------------------- RQ3 security linkage
SECURITY_SENSITIVE = {
    "aws_security_group", "aws_security_group_rule", "aws_iam_role", "aws_iam_policy",
    "aws_iam_policy_document", "aws_iam_role_policy_attachment", "aws_s3_bucket",
    "azurerm_storage_account", "aws_db_instance", "aws_kms_key",
}
def rq3_security(con, graphs):
    # map module -> repo, and module -> has security-sensitive resource
    res = con.execute("SELECT ModuleId, Type FROM Resources").fetchall()
    mod_sec = defaultdict(bool); mod_types = defaultdict(Counter)
    for r in res:
        mod_types[r["ModuleId"]][r["Type"]] += 1
        if r["Type"] in SECURITY_SENSITIVE:
            mod_sec[r["ModuleId"]] = True
    # for each repo: does it have security-sensitive resources INSIDE modules that are
    # cross-file dependency targets? (i.e. security config reached across files)
    repos_sec_crossfile = 0; repos_with_cf = 0
    for repo_id, g in graphs.items():
        cf_targets = {e["resolved_target"] for e in g["edges"] if e["cross_file"] and e["resolved_target"]}
        has_cf = any(e["cross_file"] for e in g["edges"])
        if has_cf: repos_with_cf += 1
        if any(mod_sec.get(t) for t in cf_targets):
            repos_sec_crossfile += 1
    print("\n" + "="*64); print("RQ3 — SECURITY LINKAGE"); print("="*64)
    print(f"security-sensitive resource instances: {sum(1 for r in res if r['Type'] in SECURITY_SENSITIVE)}")
    print(f"repos with a cross-file dep whose TARGET module holds security-sensitive resources:")
    print(f"   {repos_sec_crossfile}  (of {repos_with_cf} repos that have any cross-file dep)")
    print("   -> these are cases where security config is reached ACROSS files/modules,")
    print("      the population where single-file scanning is most likely to miss context.")
    return {"repos_sec_crossfile": repos_sec_crossfile, "repos_with_cf": repos_with_cf}

# ---------------------------------------------------------------- main
def main(limit_repos=None):
    db = find_db()
    if not db:
        print("TerraDS.sqlite not found."); return
    print("DB:", db)
    con = load(db)
    graphs = build_repo_graphs(con)
    if limit_repos:
        graphs = dict(list(graphs.items())[:limit_repos])
    rq1 = rq1_prevalence(graphs)
    rq2 = rq2_patterns(graphs)
    rq3 = rq3_security(con, graphs)
    con.close()
    print("\nDONE.")
    return rq1, rq2, rq3

if __name__ == "__main__":
    main()
