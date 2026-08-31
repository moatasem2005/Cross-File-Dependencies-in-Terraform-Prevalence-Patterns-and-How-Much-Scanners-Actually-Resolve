"""
Phase 6d — CORRECTED verdict logic for the boundary experiment.

BUG IN PHASE 6c (found on inspection of its own output):
The verdict compared (check_id, resource_address) pairs. When a resource is created
inside a module, Checkov prefixes the address with the module path, e.g.

    inline     : ('CKV_AWS_20', 'aws_s3_bucket.data')
    C4 module  : ('CKV_AWS_20', 'module.storage.aws_s3_bucket.data')
    C6 nested  : ('CKV_AWS_20', 'module.outer.module.inner.aws_s3_bucket.data')

The SAME check fired in every case, but the differing address made
`treatment == inline` false, so C4/C5/C6 were mislabelled "PARTIAL". They are in
fact RESOLVED. This script fixes the comparison by normalising the module prefix and
comparing on the set of check_ids.

Re-run this to confirm the corrected verdicts before writing anything in the paper.
"""
import os, subprocess, json, shutil, re

WORK = "/content/checkov_boundary2" if os.path.isdir("/content") else "./checkov_boundary2"
os.makedirs(WORK, exist_ok=True)
SECURE, INSECURE = "private", "public-read"

def sh(cmd, timeout=900):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

MODULE_PREFIX = re.compile(r"^(?:module\.[A-Za-z0-9_-]+\.)+")

def checkov_ids(path):
    """Return (set_of_check_ids, set_of_normalised_pairs).
    Normalisation strips leading module.<name>. prefixes from the resource address."""
    r = sh(["checkov","-d",path,"-o","json","--compact","--quiet"])
    out = r.stdout.strip()
    if not out: return set(), set()
    try: res = json.loads(out)
    except Exception: return set(), set()
    blocks = res if isinstance(res, list) else [res]
    ids, pairs = set(), set()
    for b in blocks:
        for f in b.get("results",{}).get("failed_checks",[]):
            cid = f.get("check_id"); rsc = f.get("resource") or ""
            ids.add(cid)
            pairs.add((cid, MODULE_PREFIX.sub("", rsc)))
    return ids, pairs

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
    d=fresh(n); w(d,"variables.tf",f'variable "bucket_acl" {{\n  type = string\n  default = "{v}"\n}}\n')
    w(d,"main.tf",BUCKET+ACL("var.bucket_acl")); return d
def c_locals(n,v):
    d=fresh(n); w(d,"locals.tf",f'locals {{\n  effective_acl = "{v}"\n}}\n')
    w(d,"main.tf",BUCKET+ACL("local.effective_acl")); return d
def c_tfvars(n,v):
    d=fresh(n); w(d,"variables.tf",f'variable "bucket_acl" {{\n  type = string\n  default = "{SECURE}"\n}}\n')
    w(d,"terraform.tfvars",f'bucket_acl = "{v}"\n'); w(d,"main.tf",BUCKET+ACL("var.bucket_acl")); return d
def c_module_input(n,v):
    d=fresh(n)
    w(d,"main.tf",'module "storage" {\n  source     = "./modules/storage"\n'+f'  bucket_acl = "{v}"\n'+'}\n')
    w(d,"modules/storage/variables.tf",'variable "bucket_acl" {\n  type = string\n  default = "private"\n}\n')
    w(d,"modules/storage/main.tf",BUCKET+ACL("var.bucket_acl")); return d
def c_module_chain(n,v):
    d=fresh(n)
    w(d,"main.tf",'module "cfg" {\n  source = "./modules/cfg"\n'+f'  acl_in = "{v}"\n'+'}\n\n'
      'module "storage" {\n  source     = "./modules/storage"\n  bucket_acl = module.cfg.acl_out\n}\n')
    w(d,"modules/cfg/variables.tf",'variable "acl_in" {\n  type = string\n}\n')
    w(d,"modules/cfg/outputs.tf",'output "acl_out" {\n  value = var.acl_in\n}\n')
    w(d,"modules/storage/variables.tf",'variable "bucket_acl" {\n  type = string\n  default = "private"\n}\n')
    w(d,"modules/storage/main.tf",BUCKET+ACL("var.bucket_acl")); return d
def c_nested(n,v):
    d=fresh(n)
    w(d,"main.tf",'module "outer" {\n  source = "./modules/outer"\n'+f'  bucket_acl = "{v}"\n'+'}\n')
    w(d,"modules/outer/variables.tf",'variable "bucket_acl" {\n  type = string\n}\n')
    w(d,"modules/outer/main.tf",'module "inner" {\n  source     = "./inner"\n  bucket_acl = var.bucket_acl\n}\n')
    w(d,"modules/outer/inner/variables.tf",'variable "bucket_acl" {\n  type = string\n  default = "private"\n}\n')
    w(d,"modules/outer/inner/main.tf",BUCKET+ACL("var.bucket_acl")); return d
def c_override(n,v):
    d=fresh(n); w(d,"main.tf",BUCKET+ACL(f'"{SECURE}"'))
    w(d,"override.tf",'resource "aws_s3_bucket_acl" "data" {\n'+f'  acl = "{v}"\n'+'}\n'); return d

CONSTRUCTS=[("C1 variable default (separate file)",c_var_default),
            ("C2 local value (separate file)",c_locals),
            ("C3 terraform.tfvars override",c_tfvars),
            ("C4 module input (local module)",c_module_input),
            ("C5 module output chaining",c_module_chain),
            ("C6 nested module (2 levels)",c_nested),
            ("C7 override.tf (last-wins)",c_override)]

def main():
    if shutil.which("checkov") is None:
        print("Installing checkov ..."); sh(["pip","install","-q","checkov"],timeout=1800)
    print("="*78)
    print("PHASE 6d — corrected boundary verdicts (module prefixes normalised)")
    print("="*78)

    ids_s,_ = checkov_ids(c_inline("inline_secure",SECURE))
    ids_i,_ = checkov_ids(c_inline("inline_insecure",INSECURE))
    signal = ids_i - ids_s
    print(f"\nInline positive control: secure={len(ids_s)} insecure={len(ids_i)}")
    print(f"  SIGNAL check(s) that indicate the insecure value: {sorted(signal)}")
    if not signal:
        print("  [!] No signal check; cannot judge constructs."); return

    rows=[]
    for label,builder in CONSTRUCTS:
        tag=label.split()[0]
        ids_c,_=checkov_ids(builder(f"{tag}_control",SECURE))
        ids_t,_=checkov_ids(builder(f"{tag}_treatment",INSECURE))
        detected = signal.issubset(ids_t) and not signal.issubset(ids_c)
        v = "RESOLVED" if detected else ("NOT RESOLVED (blind spot)"
             if signal.isdisjoint(ids_t - ids_c) else "PARTIAL")
        rows.append({"construct":label,"verdict":v,
                     "delta_ids":sorted(ids_t-ids_c)})
        print(f"\n{label}")
        print(f"   control={len(ids_c)} treatment={len(ids_t)} delta_ids={sorted(ids_t-ids_c)}")
        print(f"   => {v}")

    print("\n"+"="*78); print("CORRECTED SUMMARY (use THIS in the paper)"); print("="*78)
    print(f"{'Construct':40s} {'Verdict'}")
    print("-"*78)
    for r in rows: print(f"{r['construct']:40s} {r['verdict']}")
    n_res=sum(1 for r in rows if r["verdict"]=="RESOLVED")
    print("-"*78)
    print(f"RESOLVED: {n_res}/{len(rows)}   NOT RESOLVED: {sum(1 for r in rows if r['verdict'].startswith('NOT'))}/{len(rows)}")
    json.dump({"signal":sorted(signal),"constructs":rows},
              open(os.path.join(WORK,"corrected_boundary.json"),"w"),indent=2)
    print(f"\nSaved corrected_boundary.json to {WORK}")

if __name__=="__main__":
    main()
