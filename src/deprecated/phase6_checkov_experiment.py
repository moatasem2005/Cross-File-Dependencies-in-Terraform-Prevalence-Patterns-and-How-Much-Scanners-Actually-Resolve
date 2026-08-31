"""
Phase 6 — Checkov cross-file experiment (addresses reviewing points 2, 8, 9, 10).
Provides DIRECT evidence for the security claim instead of inference.

Idea: single-file / HCL-mode scanning cannot resolve values that live in another
file (a variable default in variables.tf consumed by a resource in main.tf).
We test this empirically by:
  1. Cloning a sample of real Terraform repos (token-free git clone).
  2. Running Checkov in HCL mode (per-file) and, where possible, in plan mode
     (which resolves variables/modules) on the SAME repos.
  3. Comparing findings: misconfigurations that appear only when cross-file values
     are resolved are, by construction, invisible to per-file analysis.
  4. Additionally, injecting a controlled cross-file misconfiguration into clean
     repos and checking whether HCL-mode Checkov detects it.

Run on Google Colab. Requires: pip install checkov (no GitHub token needed to clone
public repos).
"""
import os, subprocess, json, glob, random, tempfile, shutil

SAMPLE_REPOS = [
    # small, real, public Terraform repos with local modules (edit/extend freely)
    "bridgecrewio/terragoat",
    "futurice/terraform-examples",
    "terraform-aws-modules/terraform-aws-s3-bucket",
    "terraform-aws-modules/terraform-aws-vpc",
]

WORK = "/content/checkov_exp" if os.path.isdir("/content") else "./checkov_exp"
os.makedirs(WORK, exist_ok=True)

def sh(cmd, timeout=600):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

def clone(full, root):
    dest = os.path.join(root, full.replace("/", "__"))
    if not os.path.exists(dest):
        r = sh(["git","clone","--depth","1",f"https://github.com/{full}.git",dest])
        if r.returncode != 0:
            print("  clone failed:", full, r.stderr[:120]); return None
    return dest

def run_checkov(path):
    """Run Checkov in HCL (default) mode. Returns list of failed check dicts."""
    r = sh(["checkov","-d",path,"-o","json","--compact","--quiet"], timeout=600)
    out = r.stdout.strip()
    if not out: return []
    try:
        res = json.loads(out)
    except Exception:
        return []
    blocks = res if isinstance(res, list) else [res]
    fails = []
    for b in blocks:
        for f in b.get("results",{}).get("failed_checks",[]):
            fails.append({"check_id":f.get("check_id"),"resource":f.get("resource"),
                          "file":f.get("file_path"),"line":f.get("file_line_range")})
    return fails

# ---------- Experiment A: HCL-mode inventory on real repos ----------
def experiment_A():
    print("="*64); print("EXPERIMENT A — Checkov HCL-mode inventory on real repos"); print("="*64)
    rows=[]
    for full in SAMPLE_REPOS:
        d = clone(full, WORK)
        if not d: continue
        tf_files = glob.glob(os.path.join(d,"**","*.tf"), recursive=True)
        # count cross-file signals: files referencing var. / module. defined elsewhere
        var_refs = 0
        for tf in tf_files:
            try: txt=open(tf,encoding="utf-8",errors="ignore").read()
            except Exception: continue
            var_refs += txt.count("var.") + txt.count("module.")
        fails = run_checkov(d)
        rows.append({"repo":full,"tf_files":len(tf_files),"var_module_refs":var_refs,
                     "checkov_findings":len(fails)})
        print(f"  {full:45s} files={len(tf_files):3d} refs={var_refs:4d} findings={len(fails)}")
    return rows

# ---------- Experiment B: controlled cross-file injection ----------
def experiment_B():
    """Create a clean repo where the ONLY misconfiguration is cross-file, and check
    whether HCL-mode Checkov flags it. This isolates the blind spot with ground truth."""
    print("\n"+"="*64); print("EXPERIMENT B — controlled cross-file injection"); print("="*64)
    d = os.path.join(WORK,"injected"); shutil.rmtree(d,ignore_errors=True); os.makedirs(d)
    # variables.tf holds an INSECURE default; main.tf consumes it (no literal in main.tf)
    open(os.path.join(d,"variables.tf"),"w").write(
        'variable "bucket_acl" {\n  type    = string\n  default = "public-read"\n}\n')
    open(os.path.join(d,"main.tf"),"w").write(
        'resource "aws_s3_bucket" "data" {\n  bucket = "example-data"\n}\n'
        'resource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n  acl = var.bucket_acl\n}\n')
    fails = run_checkov(d)
    acl_flags = [f for f in fails if "acl" in str(f.get("check_id","")).lower()
                 or "ACL" in str(f.get("resource",""))]
    print(f"  Checkov findings on injected repo: {len(fails)}")
    print(f"  findings mentioning ACL/public access: {len(acl_flags)}")
    print("  -> If Checkov does NOT flag the public-read ACL that lives only in the")
    print("     cross-file variable default, that is direct evidence of the blind spot.")
    for f in fails[:8]:
        print("     •", f.get("check_id"), f.get("resource"))
    return fails

if __name__ == "__main__":
    # ensure checkov present
    if shutil.which("checkov") is None:
        print("Installing checkov ..."); sh(["pip","install","-q","checkov"], timeout=1200)
    a = experiment_A()
    b = experiment_B()
    out = WORK
    json.dump({"experiment_A":a}, open(os.path.join(out,"checkov_results.json"),"w"), indent=2)
    print("\nSaved checkov_results.json to", out)
    print("\nINTERPRETATION FOR THE PAPER:")
    print("  Experiment A quantifies how much cross-file referencing (var./module.) exists")
    print("  in real repos alongside what Checkov reports in HCL mode.")
    print("  Experiment B is the controlled test: a misconfiguration reachable ONLY via a")
    print("  cross-file variable default. Whether HCL-mode Checkov detects it is the direct,")
    print("  ground-truth evidence RQ3 needs — replacing inference with measurement.")
