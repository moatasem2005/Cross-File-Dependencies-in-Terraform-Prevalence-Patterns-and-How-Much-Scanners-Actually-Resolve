"""
Phase 6e — Multi-tool cross-file resolution (Checkov + tfsec + KICS).

Extends Phase 6d from one scanner to three, addressing the strongest generalisability
question: "why Checkov only?". Same seven constructs, same control/treatment/inline
design, same decision rule — now applied to each tool. The output is a
construct x tool matrix of RESOLVED / NOT RESOLVED / INCONCLUSIVE verdicts.

Tools:
  - checkov  (json)    : pip install checkov
  - tfsec    (json)    : binary from aquasecurity (installed below)
  - kics     (json)    : binary from Checkmarx    (installed below)

Each tool has its own "signal check": the rule id that fires for a public-read S3
ACL. We DISCOVER that signal per tool from the inline positive control rather than
hard-coding it, so the experiment is robust to differing rule identifiers.
"""
import os, subprocess, json, shutil, glob, re

WORK = "/content/multitool" if os.path.isdir("/content") else "./multitool"
os.makedirs(WORK, exist_ok=True)
SECURE, INSECURE = "private", "public-read"

def sh(cmd, timeout=1200, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)

# ----------------------------------------------------------------- construct builders
def w(path, rel, text):
    full=os.path.join(path,rel); os.makedirs(os.path.dirname(full),exist_ok=True)
    open(full,"w").write(text)
def fresh(name):
    d=os.path.join(WORK,name); shutil.rmtree(d,ignore_errors=True); os.makedirs(d); return d

BUCKET='resource "aws_s3_bucket" "data" {\n  bucket = "example-data-bucket"\n}\n\n'
ACL=lambda expr: ('resource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n'
                  f'  acl    = {expr}\n' '}\n')

def c_inline(n,v):
    d=fresh(n); w(d,"main.tf",BUCKET+ACL(f'"{v}"')); return d
def c_var_default(n,v):
    d=fresh(n); w(d,"variables.tf",f'variable "bucket_acl" {{\n  type=string\n  default="{v}"\n}}\n')
    w(d,"main.tf",BUCKET+ACL("var.bucket_acl")); return d
def c_locals(n,v):
    d=fresh(n); w(d,"locals.tf",f'locals {{\n  effective_acl="{v}"\n}}\n')
    w(d,"main.tf",BUCKET+ACL("local.effective_acl")); return d
def c_tfvars(n,v):
    d=fresh(n); w(d,"variables.tf",f'variable "bucket_acl" {{\n  type=string\n  default="{SECURE}"\n}}\n')
    w(d,"terraform.tfvars",f'bucket_acl="{v}"\n'); w(d,"main.tf",BUCKET+ACL("var.bucket_acl")); return d
def c_module_input(n,v):
    d=fresh(n)
    w(d,"main.tf",'module "storage" {\n  source="./modules/storage"\n'+f'  bucket_acl="{v}"\n'+'}\n')
    w(d,"modules/storage/variables.tf",'variable "bucket_acl" {\n  type=string\n  default="private"\n}\n')
    w(d,"modules/storage/main.tf",BUCKET+ACL("var.bucket_acl")); return d
def c_module_chain(n,v):
    d=fresh(n)
    w(d,"main.tf",'module "cfg" {\n  source="./modules/cfg"\n'+f'  acl_in="{v}"\n'+'}\n\n'
      'module "storage" {\n  source="./modules/storage"\n  bucket_acl=module.cfg.acl_out\n}\n')
    w(d,"modules/cfg/variables.tf",'variable "acl_in" {\n  type=string\n}\n')
    w(d,"modules/cfg/outputs.tf",'output "acl_out" {\n  value=var.acl_in\n}\n')
    w(d,"modules/storage/variables.tf",'variable "bucket_acl" {\n  type=string\n  default="private"\n}\n')
    w(d,"modules/storage/main.tf",BUCKET+ACL("var.bucket_acl")); return d
def c_nested(n,v):
    d=fresh(n)
    w(d,"main.tf",'module "outer" {\n  source="./modules/outer"\n'+f'  bucket_acl="{v}"\n'+'}\n')
    w(d,"modules/outer/variables.tf",'variable "bucket_acl" {\n  type=string\n}\n')
    w(d,"modules/outer/main.tf",'module "inner" {\n  source="./inner"\n  bucket_acl=var.bucket_acl\n}\n')
    w(d,"modules/outer/inner/variables.tf",'variable "bucket_acl" {\n  type=string\n  default="private"\n}\n')
    w(d,"modules/outer/inner/main.tf",BUCKET+ACL("var.bucket_acl")); return d
def c_override(n,v):
    d=fresh(n); w(d,"main.tf",BUCKET+ACL(f'"{SECURE}"'))
    w(d,"override.tf",'resource "aws_s3_bucket_acl" "data" {\n'+f'  acl="{v}"\n'+'}\n'); return d

CONSTRUCTS=[("C1 variable default",c_var_default),
            ("C2 local value",c_locals),
            ("C3 terraform.tfvars",c_tfvars),
            ("C4 module input",c_module_input),
            ("C5 module output chaining",c_module_chain),
            ("C6 nested module (2 levels)",c_nested),
            ("C7 override.tf",c_override)]

# ----------------------------------------------------------------- per-tool runners
MODULE_PREFIX = re.compile(r"^(?:module\.[A-Za-z0-9_-]+\.)+")

def run_checkov(path):
    r=sh(["checkov","-d",path,"-o","json","--compact","--quiet"])
    out=r.stdout.strip()
    if not out: return set()
    try: res=json.loads(out)
    except Exception: return set()
    blocks=res if isinstance(res,list) else [res]
    ids=set()
    for b in blocks:
        for f in b.get("results",{}).get("failed_checks",[]):
            ids.add(f.get("check_id"))
    return ids

def run_tfsec(path):
    if not shutil.which("tfsec"): return set()
    r=sh(["tfsec",path,"-f","json","--no-colour","--soft-fail"])
    out=r.stdout.strip()
    if not out or not out.startswith("{"):
        # tfsec may print a banner; try to find the json object
        m=re.search(r"\{.*\}", out, re.S)
        out=m.group(0) if m else ""
    if not out: return set()
    try: res=json.loads(out)
    except Exception: return set()
    ids=set()
    for res_item in (res.get("results") or []):
        ids.add(res_item.get("long_id") or res_item.get("rule_id"))
    return ids

def run_kics(path):
    if not shutil.which("kics"): return set()
    outdir=os.path.join(path,"_kics"); os.makedirs(outdir,exist_ok=True)
    qp=os.environ.get("KICS_QUERIES_PATH")
    kics_cmd=["kics","scan","-p",path,"--report-formats","json","-o",outdir,
              "--silent","--no-progress"]
    if qp: kics_cmd+=["-q",qp]
    r=sh(kics_cmd, timeout=1800)
    js=glob.glob(os.path.join(outdir,"*.json"))
    if not js: return set()
    try: res=json.load(open(js[0]))
    except Exception: return set()
    ids=set()
    for q in res.get("queries",[]):
        if q.get("files"):
            ids.add(q.get("query_id") or q.get("query_name"))
    return ids

TOOLS={"checkov":run_checkov,"tfsec":run_tfsec,"kics":run_kics}

def verdict(signal, ctrl, treat):
    if not signal: return "INCONCLUSIVE (no signal)"
    if signal.issubset(treat) and not signal.issubset(ctrl): return "RESOLVED"
    if signal.isdisjoint(treat - ctrl): return "NOT RESOLVED"
    return "PARTIAL"

def which(tool): return shutil.which(tool) is not None

def main():
    print("="*80); print("PHASE 6e — cross-file resolution across Checkov, tfsec, KICS"); print("="*80)
    available={name:which(name) for name in TOOLS}
    print("tool availability:", available)

    # discover each tool's signal from the inline positive control
    isec=c_inline("inline_secure",SECURE)
    iins=c_inline("inline_insecure",INSECURE)
    signals={}
    for name,run in TOOLS.items():
        if not available[name]: continue
        s=run(iins)-run(isec)
        signals[name]=s
        print(f"  [{name}] signal check(s) for public-read ACL: {sorted(s) if s else 'NONE (rule missing?)'}")

    matrix={}
    for label,builder in CONSTRUCTS:
        tag=label.split()[0]
        matrix[label]={}
        for name,run in TOOLS.items():
            if not available[name] or not signals.get(name):
                matrix[label][name]="N/A"; continue
            ctrl=run(builder(f"{tag}_{name}_ctrl",SECURE))
            treat=run(builder(f"{tag}_{name}_treat",INSECURE))
            matrix[label][name]=verdict(signals[name],ctrl,treat)

    print("\n"+"="*80); print("RESULT MATRIX (construct x tool)"); print("="*80)
    tools=[t for t in TOOLS if available[t] and signals.get(t)]
    print(f"{'Construct':32s} " + " ".join(f"{t:>14s}" for t in tools))
    print("-"*80)
    for label in matrix:
        print(f"{label:32s} " + " ".join(f"{matrix[label][t]:>14s}" for t in tools))

    json.dump({"signals":{k:sorted(v) for k,v in signals.items()},"matrix":matrix},
              open(os.path.join(WORK,"multitool_results.json"),"w"),indent=2)
    print(f"\nSaved multitool_results.json to {WORK}")
    print("\nREAD: a construct RESOLVED by all available tools is strongly resolved;")
    print("one NOT RESOLVED across tools is a robust cross-tool blind spot.")

if __name__=="__main__":
    main()
