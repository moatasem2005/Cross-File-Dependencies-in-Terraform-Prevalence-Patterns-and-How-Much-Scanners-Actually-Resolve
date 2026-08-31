"""
Phase 4 — Deepening + publication-ready figures & tables.
Builds on Phase 3's graph construction and produces:
  - RQ1: distribution figure (log-scale histogram + CCDF) of cross-file edges/repo
  - RQ2: pattern taxonomy bar chart + a concrete real example per pattern
  - RQ3: which security-sensitive resource TYPES are reached cross-file (breakdown + fig)
  - LaTeX-ready tables for all three.
Tested on an expanded mock mirroring the TerraDS schema.
"""

# --- canonical shared logic (single source of truth) ---
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from core import (classify_source as _classify_source, is_cross_file as _is_cross_file,
                  resolve_local_module as _resolve_local_module,
                  normalise_module_path as _normalise_module_path,
                  SECURITY_SENSITIVE_RESOURCES as _SEC)

def classify(src):
    """Delegates to core.classify_source (kept for backward compatibility)."""
    return _classify_source(src)

def classify_source(src):
    return _classify_source(src)

def is_cf(k):
    return _is_cross_file(k)

SEC = _SEC

import sqlite3, json, os, re, glob
from collections import Counter, defaultdict
import statistics as st
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ---- reuse Phase 3 core (inlined so this notebook is standalone) ----
def find_db():
    for p in ["data/terrads/TerraDS.sqlite", "/content/terrads/TerraDS.sqlite", "data/TerraDS.sqlite"]:
        if os.path.exists(p): return p
    hits = glob.glob("/content/**/TerraDS.sqlite", recursive=True) + glob.glob("**/TerraDS.sqlite", recursive=True)
    return hits[0] if hits else None


def is_cross_file(k): return k in ("local_subdir","local_traversal")

SECURITY_SENSITIVE = {
    "aws_security_group","aws_security_group_rule","aws_iam_role","aws_iam_policy",
    "aws_iam_policy_document","aws_iam_role_policy_attachment","aws_s3_bucket",
    "azurerm_storage_account","aws_db_instance","aws_kms_key",
}

def build_graphs(con):
    mods = con.execute("SELECT Id,RepositoryId,Path,ModuleCalls FROM Modules").fetchall()
    by_repo = defaultdict(list)
    for m in mods: by_repo[m["RepositoryId"]].append(m)
    graphs = {}
    for repo_id, modlist in by_repo.items():
        path_index = {(m["Path"] or "").strip("/").replace("\\","/"): m["Id"] for m in modlist}
        edges = []
        for m in modlist:
            raw = m["ModuleCalls"]
            if not raw or raw in ("[]",""): continue
            try: calls = json.loads(raw)
            except Exception: continue
            src_dir = (m["Path"] or "").strip("/").replace("\\","/")
            for call in calls:
                src = call.get("source",""); kind = classify_source(src)
                rid = None
                if is_cross_file(kind):
                    joined = os.path.normpath(os.path.join(src_dir, src)).replace("\\","/")
                    target = (joined[2:] if joined.startswith("./") else joined).strip("/")
                    rid = path_index.get(target)
                edges.append({"src_module":m["Id"],"source":src,"kind":kind,
                              "cross_file":is_cross_file(kind),"resolved_target":rid})
        graphs[repo_id] = {"modules":modlist,"edges":edges}
    return graphs

# ---------------------------------------------------------------- RQ1 figure
def rq1_figure(graphs, outdir):
    cf = [sum(1 for e in g["edges"] if e["cross_file"]) for g in graphs.values()]
    cf_pos = [x for x in cf if x > 0]
    fig, ax = plt.subplots(1, 2, figsize=(12,4.2))
    # (a) histogram of cross-file edge count (repos with >=1), log y
    ax[0].hist(cf_pos, bins=40, color="#2a7", edgecolor="white")
    ax[0].set_yscale("log")
    ax[0].set_xlabel("cross-file edges per repository")
    ax[0].set_ylabel("number of repositories (log)")
    ax[0].set_title("(a) Distribution of cross-file dependencies")
    # (b) CCDF
    xs = np.sort(cf_pos); ccdf = 1.0 - np.arange(len(xs))/len(xs)
    ax[1].plot(xs, ccdf, color="#c60")
    ax[1].set_xscale("log"); ax[1].set_yscale("log")
    ax[1].set_xlabel("cross-file edges per repository (log)")
    ax[1].set_ylabel("P(X >= x) (log)")
    ax[1].set_title("(b) CCDF — heavy tail")
    plt.tight_layout()
    p = os.path.join(outdir, "rq1_distribution.png"); plt.savefig(p, dpi=140, bbox_inches="tight"); plt.close()
    total = len(graphs); withcf = len(cf_pos)
    print(f"RQ1: {withcf}/{total} repos ({100*withcf/total:.1f}%) have >=1 cross-file dep")
    if cf_pos:
        print(f"     among them: median={st.median(cf_pos)} mean={st.mean(cf_pos):.2f} "
              f"p90={np.percentile(cf_pos,90):.0f} max={max(cf_pos)}")
    print(f"     figure -> {p}")
    return {"repos_total":total,"repos_with_cf":withcf}

# ---------------------------------------------------------------- RQ2 taxonomy + examples
def rq2_taxonomy(graphs, outdir):
    kinds = Counter(); example = {}
    for g in graphs.values():
        for e in g["edges"]:
            kinds[e["kind"]] += 1
            example.setdefault(e["kind"], e["source"])
    labels, vals = zip(*kinds.most_common())
    fig, ax = plt.subplots(figsize=(8,4))
    colors = ["#2a7" if is_cross_file(k) else "#bbb" for k in labels]
    ax.bar(labels, vals, color=colors)
    ax.set_ylabel("dependency count"); ax.set_title("RQ2 — module dependency patterns (green = cross-file)")
    plt.xticks(rotation=30, ha="right"); plt.tight_layout()
    p = os.path.join(outdir, "rq2_patterns.png"); plt.savefig(p, dpi=140, bbox_inches="tight"); plt.close()
    total = sum(kinds.values()) or 1
    print("\nRQ2 taxonomy:")
    latex = ["\\begin{tabular}{lrrl}","\\toprule","Pattern & Count & \\% & Example source \\\\","\\midrule"]
    for k,c in kinds.most_common():
        ex = example[k][:38].replace("_","\\_")
        print(f"  {k:16s} {c:8d} ({100*c/total:5.1f}%)  e.g. {example[k][:50]}")
        latex.append(f"{k.replace('_',' ')} & {c} & {100*c/total:.1f} & \\texttt{{{ex}}} \\\\")
    latex += ["\\bottomrule","\\end{tabular}"]
    open(os.path.join(outdir,"rq2_table.tex"),"w").write("\n".join(latex))
    print(f"  figure -> {p} | table -> rq2_table.tex")
    return dict(kinds)

# ---------------------------------------------------------------- RQ3 security breakdown
def rq3_security(con, graphs, outdir):
    res = con.execute("SELECT ModuleId,Type FROM Resources").fetchall()
    mod_types = defaultdict(Counter)
    for r in res: mod_types[r["ModuleId"]][r["Type"]] += 1
    # count security-sensitive TYPES reached as cross-file targets
    reached = Counter(); repos_hit = 0; repos_cf = 0
    for g in graphs.values():
        cf_targets = {e["resolved_target"] for e in g["edges"] if e["cross_file"] and e["resolved_target"]}
        has_cf = any(e["cross_file"] for e in g["edges"])
        if has_cf: repos_cf += 1
        hit = False
        for t in cf_targets:
            for typ,cnt in mod_types.get(t,{}).items():
                if typ in SECURITY_SENSITIVE:
                    reached[typ] += cnt; hit = True
        if hit: repos_hit += 1
    print("\nRQ3 security linkage:")
    print(f"  repos with cross-file dep reaching security-sensitive module: "
          f"{repos_hit}/{repos_cf} ({100*repos_hit/max(repos_cf,1):.1f}% of cross-file repos)")
    if reached:
        fig, ax = plt.subplots(figsize=(8,4))
        labels, vals = zip(*reached.most_common(10))
        ax.barh(labels[::-1], vals[::-1], color="#c0392b")
        ax.set_xlabel("instances reached via cross-file dependency")
        ax.set_title("RQ3 — security-sensitive resource types reached across files")
        plt.tight_layout()
        p = os.path.join(outdir,"rq3_security_types.png"); plt.savefig(p,dpi=140,bbox_inches="tight"); plt.close()
        print("  top reached types:")
        for t,c in reached.most_common(10): print(f"    {c:8d}  {t}")
        print(f"  figure -> {p}")
    return {"repos_hit":repos_hit,"repos_cf":repos_cf,"reached_types":dict(reached)}

def main():
    db = find_db()
    if not db: print("TerraDS.sqlite not found"); return
    print("DB:", db)
    outdir = "/content/drive/MyDrive/terrads_phase4" if os.path.isdir("/content/drive") else "/content/phase4_out"
    os.makedirs(outdir, exist_ok=True)
    con = sqlite3.connect(db); con.row_factory = sqlite3.Row
    graphs = build_graphs(con)
    r1 = rq1_figure(graphs, outdir)
    r2 = rq2_taxonomy(graphs, outdir)
    r3 = rq3_security(con, graphs, outdir)
    con.close()
    json.dump({"RQ1":r1,"RQ2":r2,"RQ3":r3}, open(os.path.join(outdir,"phase4_results.json"),"w"), indent=2)
    print(f"\nAll figures + tables + results saved to: {outdir}")
    for f in sorted(os.listdir(outdir)):
        print("   ", f, os.path.getsize(os.path.join(outdir,f)), "bytes")

if __name__ == "__main__":
    main()
