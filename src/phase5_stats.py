"""
Phase 5 — Statistical analysis (explanatory statistics for the study).
Builds a per-repository dataset from TerraDS and runs:
  - RQ1: Spearman/Pearson correlation (repo size, forks, stars vs cross-file count),
         + power-law vs log-normal fit of the cross-file distribution with a
           Kolmogorov-Smirnov goodness-of-fit test (heavy-tail claim, validated).
  - RQ3: logistic regression predicting whether a repo has a cross-file dependency
         that reaches a security-sensitive module, with odds ratios + effect sizes;
         chi-square and Mann-Whitney tests for group differences.
Uses scipy + sklearn only (statsmodels/powerlaw optional; we implement MLE+KS by hand).
Tested on a skewed synthetic mock mirroring the TerraDS schema.
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

import sqlite3, json, os, glob, math
import numpy as np
from collections import defaultdict, Counter
from scipy import stats
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score

# ---- reuse graph construction (module-level) ----
def find_db():
    for p in ["data/terrads/TerraDS.sqlite","/content/terrads/TerraDS.sqlite","/tmp/mock/TerraDS.sqlite"]:
        if os.path.exists(p): return p
    h=glob.glob("/content/**/TerraDS.sqlite",recursive=True)+glob.glob("**/TerraDS.sqlite",recursive=True)
    return h[0] if h else None



SEC = _SEC

def build_per_repo_table(con):
    """One row per repository with structural + metadata + outcome columns."""
    # module metadata
    mods=con.execute("SELECT Id,RepositoryId,Path,ModuleCalls FROM Modules").fetchall()
    by_repo=defaultdict(list)
    for m in mods: by_repo[m["RepositoryId"]].append(m)
    # resource security flag per module
    mod_sec=defaultdict(bool)
    for r in con.execute("SELECT ModuleId,Type FROM Resources").fetchall():
        if r["Type"] in SEC: mod_sec[r["ModuleId"]]=True
    # repo metadata
    repo_meta={r["Id"]:r for r in con.execute(
        "SELECT Id,StarCount,ForkCount,SizeInKb,Archived FROM Repositories").fetchall()}

    rows=[]
    for repo_id, modlist in by_repo.items():
        path_index={(m["Path"] or "").strip("/").replace("\\","/"):m["Id"] for m in modlist}
        n_modules=len(modlist); cf_edges=0; total_edges=0; cf_targets=set()
        for m in modlist:
            raw=m["ModuleCalls"]
            if not raw or raw in ("[]",""): continue
            try: calls=json.loads(raw)
            except Exception: continue
            sd=(m["Path"] or "").strip("/").replace("\\","/")
            for call in calls:
                total_edges+=1; k=classify(call.get("source",""))
                if is_cf(k):
                    cf_edges+=1
                    j=os.path.normpath(os.path.join(sd,call.get("source",""))).replace("\\","/")
                    tgt=(j[2:] if j.startswith("./") else j).strip("/")
                    if path_index.get(tgt): cf_targets.add(path_index[tgt])
        meta=repo_meta.get(repo_id)
        sec_reached=any(mod_sec.get(t) for t in cf_targets)
        rows.append({
            "repo_id":repo_id,"n_modules":n_modules,"total_edges":total_edges,
            "cf_edges":cf_edges,"has_cf":int(cf_edges>0),
            "sec_reached":int(sec_reached),
            "stars":(meta["StarCount"] if meta else 0) or 0,
            "forks":(meta["ForkCount"] if meta else 0) or 0,
            "size_kb":(meta["SizeInKb"] if meta else 0) or 0,
        })
    return rows

# ---------------- RQ1: correlations ----------------
def rq1_correlations(rows):
    import numpy as np
    x_size=np.array([r["size_kb"] for r in rows],float)
    x_forks=np.array([r["forks"] for r in rows],float)
    x_stars=np.array([r["stars"] for r in rows],float)
    x_mods=np.array([r["n_modules"] for r in rows],float)
    y=np.array([r["cf_edges"] for r in rows],float)
    print("="*64); print("RQ1 — CORRELATION with cross-file edge count"); print("="*64)
    for name,x in [("repo size (KB)",x_size),("forks",x_forks),("stars",x_stars),("#modules",x_mods)]:
        rho,p=stats.spearmanr(x,y)
        print(f"  Spearman  cf_edges ~ {name:16s}: rho={rho:+.3f}  p={p:.2e}")
    # Pearson on log1p to tame skew
    for name,x in [("repo size (KB)",x_size),("#modules",x_mods)]:
        r,p=stats.pearsonr(np.log1p(x),np.log1p(y))
        print(f"  Pearson(log) cf_edges ~ {name:16s}: r={r:+.3f}  p={p:.2e}")

# ---------------- RQ1: heavy-tail validation ----------------
def powerlaw_ks(data, xmin=1):
    """MLE power-law exponent (discrete approx via continuous MLE) + KS distance."""
    d=np.array([v for v in data if v>=xmin],float)
    n=len(d)
    if n<10: return None
    alpha=1.0+n/np.sum(np.log(d/(xmin-0.5)))   # Clauset et al. discrete MLE approx
    # KS between empirical CDF and fitted power-law CDF
    xs=np.sort(d)
    cdf_emp=np.arange(1,n+1)/n
    cdf_fit=1-(xs/xmin)**(-(alpha-1))
    ks=np.max(np.abs(cdf_emp-cdf_fit))
    return alpha,ks,n

def rq1_heavytail(rows):
    cf=[r["cf_edges"] for r in rows if r["cf_edges"]>0]
    print("\n"+"="*64); print("RQ1 — HEAVY-TAIL VALIDATION"); print("="*64)
    arr=np.array(cf,float)
    print(f"  n(>0)={len(arr)}  mean={arr.mean():.2f}  median={np.median(arr):.0f}  max={arr.max():.0f}")
    print(f"  skewness={stats.skew(arr):.2f}  kurtosis={stats.kurtosis(arr):.2f}")
    pl=powerlaw_ks(arr,xmin=1)
    if pl:
        alpha,ks,n=pl
        print(f"  power-law MLE exponent alpha={alpha:.3f} (xmin=1, n={n})")
        print(f"  KS distance (power-law fit) D={ks:.4f}")
    # lognormal fit + KS for comparison
    logd=np.log(arr); mu,sig=logd.mean(),logd.std()
    ks_ln,p_ln=stats.kstest(arr,'lognorm',args=(sig,0,np.exp(mu)))
    print(f"  lognormal fit: mu={mu:.2f} sigma={sig:.2f} | KS D={ks_ln:.4f} p={p_ln:.2e}")
    print("  (lower KS D = better fit; compare power-law vs lognormal)")

# ---------------- RQ3: logistic regression + tests ----------------
def rq3_logit(rows):
    print("\n"+"="*64); print("RQ3 — LOGISTIC REGRESSION: predict sec_reached"); print("="*64)
    # only repos that HAVE a cross-file dep (the population at risk)
    sub=[r for r in rows if r["has_cf"]==1]
    if len(sub)<50: print("  too few cross-file repos in this dataset"); return
    X=np.array([[math.log1p(r["n_modules"]),math.log1p(r["cf_edges"]),
                 math.log1p(r["size_kb"]),math.log1p(r["stars"])] for r in sub],float)
    y=np.array([r["sec_reached"] for r in sub])
    names=["log(#modules)","log(cf_edges)","log(size_kb)","log(stars)"]
    Xs=StandardScaler().fit_transform(X)
    clf=LogisticRegression(max_iter=1000).fit(Xs,y)
    auc=roc_auc_score(y,clf.predict_proba(Xs)[:,1])
    print(f"  n={len(sub)}  positives(sec_reached)={int(y.sum())}  model AUC={auc:.3f}")
    print("  standardized coefficients (odds ratio per +1 SD):")
    for nm,c in zip(names,clf.coef_[0]):
        print(f"    {nm:16s} beta={c:+.3f}  OR={math.exp(c):.2f}")
    # Mann-Whitney: cf_edges for sec_reached vs not
    a=[r["cf_edges"] for r in sub if r["sec_reached"]==1]
    b=[r["cf_edges"] for r in sub if r["sec_reached"]==0]
    if a and b:
        u,p=stats.mannwhitneyu(a,b,alternative="two-sided")
        # rank-biserial effect size
        rbc=1-2*u/(len(a)*len(b))
        print(f"  Mann-Whitney cf_edges (sec vs non-sec): U={u:.0f} p={p:.2e} rank-biserial={rbc:+.3f}")
    # Chi-square: has many modules (>median) vs sec_reached
    med=np.median([r["n_modules"] for r in sub])
    tab=np.zeros((2,2),int)
    for r in sub:
        tab[int(r["n_modules"]>med)][r["sec_reached"]]+=1
    chi2,p,dof,_=stats.chi2_contingency(tab)
    phi=math.sqrt(chi2/len(sub))
    print(f"  Chi-square (#modules>median vs sec_reached): chi2={chi2:.2f} p={p:.2e} phi={phi:.3f}")


# ---------------- Resolver validation (methodological validation) ----------------
def resolver_validation(con, sample_n=200, seed=42):
    """Quantify resolver behaviour: of local cross-file edges, how many resolve to an
    in-repo module (recall proxy); sample and report for manual precision auditing."""
    import random as _r
    _r.seed(seed)
    mods=con.execute("SELECT Id,RepositoryId,Path,ModuleCalls FROM Modules").fetchall()
    by_repo=defaultdict(list)
    for m in mods: by_repo[m["RepositoryId"]].append(m)
    total_cf=0; resolved=0; sample=[]
    for repo_id,modlist in by_repo.items():
        path_index={(m["Path"] or "").strip("/").replace("\\","/"):m["Id"] for m in modlist}
        for m in modlist:
            raw=m["ModuleCalls"]
            if not raw or raw in ("[]",""): continue
            try: calls=json.loads(raw)
            except Exception: continue
            sd=(m["Path"] or "").strip("/").replace("\\","/")
            for call in calls:
                k=classify(call.get("source",""))
                if not is_cf(k): continue
                total_cf+=1
                j=os.path.normpath(os.path.join(sd,call.get("source",""))).replace("\\","/")
                tgt=(j[2:] if j.startswith("./") else j).strip("/")
                ok=tgt in path_index
                if ok: resolved+=1
                if len(sample)<sample_n:
                    sample.append({"src_dir":sd,"source":call.get("source",""),"target":tgt,"resolved":ok})
    print("\n"+"="*64); print("RESOLVER VALIDATION"); print("="*64)
    print(f"  total local cross-file edges: {total_cf}")
    print(f"  resolved to in-repo module:   {resolved} ({100*resolved/max(total_cf,1):.1f}%)")
    print(f"  unresolved:                   {total_cf-resolved} ({100*(total_cf-resolved)/max(total_cf,1):.1f}%)")
    print(f"  -> {len(sample)} edges written for MANUAL precision audit (resolver_audit.csv)")
    out="/content/phase5_out" if os.path.isdir("/content") else "phase5_out"
    os.makedirs(out,exist_ok=True)
    import csv
    with open(os.path.join(out,"resolver_audit.csv"),"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["src_dir","source","target","resolved"]); w.writeheader(); w.writerows(sample)



# --- model comparison: Vuong test and thin-tailed baselines --------------------
def compare_tail_models(counts):
    """Compare a discrete power law against a log-normal (Vuong), and both against
    thin-tailed baselines. The manuscript cites this test, so it lives in the code."""
    import numpy as _np, math as _m
    from scipy import stats as _st
    from scipy.special import zeta as _zeta
    from scipy.optimize import minimize_scalar as _mini
    from scipy.stats import lognorm as _ln
    d = _np.asarray([c for c in counts if c > 0], dtype=int)
    n = len(d)
    if n < 50:
        print("  too few positive counts for model comparison"); return
    nll = lambda a: 1e9 if a <= 1 else -(-a*_np.sum(_np.log(d)) - n*_m.log(_zeta(a, 1)))
    alpha = _mini(nll, bounds=(1.01, 5), method="bounded").x
    xs = _np.sort(d); ecdf = _np.arange(1, n+1)/n
    ks_pl = _np.max(_np.abs(ecdf - (1 - _zeta(alpha, xs+1)/_zeta(alpha, 1))))
    logd = _np.log(d); mu, sig = logd.mean(), logd.std()
    ks_ln = _np.max(_np.abs(ecdf - _ln.cdf(xs, sig, scale=_m.exp(mu))))
    ll_pl = -alpha*_np.log(d) - _m.log(_zeta(alpha, 1))
    ll_ln = _np.log(_np.maximum(_ln.cdf(d+0.5, sig, scale=_m.exp(mu))
                                - _ln.cdf(_np.maximum(d-0.5, 1e-9), sig, scale=_m.exp(mu)), 1e-300))
    R = ll_pl - ll_ln
    V = _m.sqrt(n)*R.mean()/R.std()
    pV = 2*(1 - _st.norm.cdf(abs(V)))
    ll_pois = _st.poisson.logpmf(d, d.mean()).sum()
    ll_geo = _st.geom.logpmf(d, 1/d.mean()).sum()
    print("\n" + "="*64); print("TAIL MODEL COMPARISON"); print("="*64)
    print(f"  n = {n:,}")
    print(f"  power law (zeta) alpha={alpha:.3f}  KS D={ks_pl:.3f}  loglik={ll_pl.sum():.0f}")
    print(f"  log-normal mu={mu:.3f} sigma={sig:.3f}  KS D={ks_ln:.3f}  loglik={ll_ln.sum():.0f}")
    print(f"  Vuong V={V:.2f}  p={pV:.2e}  -> favours {'power law' if V > 0 else 'log-normal'}")
    print(f"  thin-tailed baselines: Poisson loglik={ll_pois:.0f}  geometric loglik={ll_geo:.0f}")
    print(f"  both heavy-tailed models beat both thin-tailed baselines: "
          f"{min(ll_pl.sum(), ll_ln.sum()) > max(ll_pois, ll_geo)}")
    return {"alpha": alpha, "ks_power_law": ks_pl, "mu": mu, "sigma": sig,
            "ks_lognormal": ks_ln, "vuong_V": V, "vuong_p": pV,
            "loglik_power_law": ll_pl.sum(), "loglik_lognormal": ll_ln.sum(),
            "loglik_poisson": ll_pois, "loglik_geometric": ll_geo}


def main():
    db=find_db()
    if not db: print("DB not found"); return
    print("DB:",db)
    con=sqlite3.connect(db); con.row_factory=sqlite3.Row
    rows=build_per_repo_table(con); con.close()
    print(f"per-repo rows: {len(rows)}")
    rq1_correlations(rows)
    rq1_heavytail(rows)
    compare_tail_models([r['cf_edges'] for r in rows])
    rq3_logit(rows)
    con2=sqlite3.connect(db); con2.row_factory=sqlite3.Row
    resolver_validation(con2); con2.close()
    # persist per-repo table for the paper's replication
    out="/content/phase5_out" if os.path.isdir("/content") else "phase5_out"
    os.makedirs(out,exist_ok=True)
    import csv
    with open(os.path.join(out,"per_repo.csv"),"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print(f"\nper-repo table saved to {out}/per_repo.csv ({len(rows)} rows)")

if __name__=="__main__":
    main()

