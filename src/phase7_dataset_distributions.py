"""
Phase 7 — Dataset distributions + unresolved-edge breakdown (methodological validation).

Part A: characterise the TerraDS corpus so readers can judge generalisability:
  - cloud provider distribution (from Modules.Providers)
  - repository size, stars, forks distributions (quartiles)
  - repository age (CreatedAt -> years) and recency (LatestCommitAt)
  - modules-per-repo distribution
Part B: classify WHY 4.5% of local cross-file edges did not resolve to an in-repo
  module, turning an unexplained residual into a categorised breakdown:
  - parent_traversal_escapes_repo : '../' path climbs above the indexed module set
  - target_dir_not_indexed        : resolved path has no matching module row
  - malformed_or_empty_source     : blank/º unpardable source
  - non_local (safety check)      : should be zero here (locals only)
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

import sqlite3, json, os, glob, re, statistics as st
from collections import Counter, defaultdict

def find_db():
    for p in ["data/terrads/TerraDS.sqlite","/content/terrads/TerraDS.sqlite","/tmp/mock/TerraDS.sqlite"]:
        if os.path.exists(p): return p
    h=glob.glob("/content/**/TerraDS.sqlite",recursive=True)+glob.glob("**/TerraDS.sqlite",recursive=True)
    return h[0] if h else None

def quart(xs):
    xs=sorted(x for x in xs if x is not None)
    if not xs: return None
    n=len(xs)
    q=lambda p: xs[min(n-1,int(p*n))]
    return {"min":xs[0],"q1":q(0.25),"median":q(0.5),"q3":q(0.75),
            "p90":q(0.90),"max":xs[-1],"mean":round(sum(xs)/n,1)}

# ---------------- Part A ----------------
def part_a(con):
    print("="*70); print("PART A — DATASET DISTRIBUTIONS"); print("="*70)

    # provider distribution
    prov=Counter()
    for (p,) in con.execute("SELECT Providers FROM Modules WHERE Providers IS NOT NULL AND Providers!='[]'"):
        try:
            for x in json.loads(p): prov[x]+=1
        except Exception: pass
    total_prov=sum(prov.values()) or 1
    print("\nCloud/provider distribution (top 12 by module count):")
    for name,c in prov.most_common(12):
        print(f"  {name:16s} {c:8d}  ({100*c/total_prov:.1f}%)")

    # repo-level metadata (defensive: some columns may be absent in variant schemas)
    cols=[c[1] for c in con.execute("PRAGMA table_info('Repositories')").fetchall()]
    want=[c for c in ["StarCount","ForkCount","SizeInKb","CreatedAt","LatestCommitAt","Archived"] if c in cols]
    rows=con.execute(f"SELECT {','.join(want)} FROM Repositories").fetchall()
    col_idx={name:i for i,name in enumerate(want)}
    def col(r,name): 
        i=col_idx.get(name); return r[i] if i is not None else None
    stars=[col(r,"StarCount") or 0 for r in rows]
    forks=[col(r,"ForkCount") or 0 for r in rows]
    size=[col(r,"SizeInKb") or 0 for r in rows]
    print("\nRepository size (KB):", quart(size))
    print("Stars:", quart(stars))
    print("Forks:", quart(forks))

    import datetime as dt
    def year(s):
        try: return int(str(s)[:4])
        except Exception: return None
    created=[year(col(r,"CreatedAt")) for r in rows]; created=[c for c in created if c]
    latest=[year(col(r,"LatestCommitAt")) for r in rows]; latest=[c for c in latest if c]
    if created:
        cc=Counter(created)
        print("\nRepository creation year (distribution):")
        for y in sorted(cc): print(f"  {y}: {cc[y]}")
    if latest:
        lc=Counter(latest)
        print("\nLatest commit year (recency):")
        for y in sorted(lc): print(f"  {y}: {lc[y]}")
    archived=sum(1 for r in rows if col(r,"Archived")==1)
    print(f"\nArchived repositories: {archived} ({100*archived/len(rows):.1f}%)")

    # modules per repo
    mpr=[c for (c,) in con.execute("SELECT COUNT(*) FROM Modules GROUP BY RepositoryId")]
    print("\nModules per repository:", quart(mpr))

# ---------------- Part B ----------------

def part_b(con):
    print("\n"+"="*70); print("PART B — WHY 4.5% OF CROSS-FILE EDGES DON'T RESOLVE"); print("="*70)
    mods=con.execute("SELECT Id,RepositoryId,Path,ModuleCalls FROM Modules").fetchall()
    by_repo=defaultdict(list)
    for m in mods: by_repo[m[1]].append(m)

    reasons=Counter(); total_cf=0; resolved=0; examples=defaultdict(list)
    for repo_id, modlist in by_repo.items():
        path_index={ (m[2] or "").strip("/").replace("\\","/"): m[0] for m in modlist }
        for m in modlist:
            raw=m[3]
            if not raw or raw in ("[]",""): continue
            try: calls=json.loads(raw)
            except Exception: continue
            sd=(m[2] or "").strip("/").replace("\\","/")
            for call in calls:
                src=(call.get("source") or "")
                kind=classify_source(src)
                if kind not in ("local_subdir","local_traversal"): continue
                total_cf+=1
                if not src.strip():
                    reasons["malformed_or_empty_source"]+=1; continue
                joined=os.path.normpath(os.path.join(sd,src)).replace("\\","/")
                tgt=(joined[2:] if joined.startswith("./") else joined).strip("/")
                if tgt in path_index:
                    resolved+=1; continue
                # unresolved: categorise
                if joined.startswith("..") or tgt.startswith(".."):
                    reasons["parent_traversal_escapes_repo"]+=1
                    if len(examples["parent_traversal_escapes_repo"])<5:
                        examples["parent_traversal_escapes_repo"].append(f"{sd} + {src}")
                else:
                    reasons["target_dir_not_indexed"]+=1
                    if len(examples["target_dir_not_indexed"])<5:
                        examples["target_dir_not_indexed"].append(f"{sd} + {src} -> {tgt}")

    unresolved=total_cf-resolved
    print(f"\ntotal local cross-file edges: {total_cf}")
    print(f"resolved: {resolved} ({100*resolved/max(total_cf,1):.1f}%)")
    print(f"unresolved: {unresolved} ({100*unresolved/max(total_cf,1):.1f}%)")
    print("\nUnresolved breakdown by cause:")
    for r,c in reasons.most_common():
        pct_all=100*c/max(total_cf,1); pct_unres=100*c/max(unresolved,1)
        print(f"  {r:32s} {c:6d}  ({pct_unres:.1f}% of unresolved, {pct_all:.2f}% of all)")
    print("\nExamples:")
    for r,exs in examples.items():
        print(f"  [{r}]")
        for e in exs: print(f"     {e}")

    out="/content/phase7_out" if os.path.isdir("/content") else "phase7_out"
    os.makedirs(out,exist_ok=True)
    json.dump({"total_cf":total_cf,"resolved":resolved,"unresolved":unresolved,
               "reasons":dict(reasons)}, open(os.path.join(out,"unresolved_breakdown.json"),"w"),indent=2)
    print(f"\nSaved unresolved_breakdown.json to {out}")

def main():
    db=find_db()
    if not db: print("DB not found"); return
    print("DB:",db)
    con=sqlite3.connect(db)
    part_a(con)
    part_b(con)
    con.close()

if __name__=="__main__":
    main()
