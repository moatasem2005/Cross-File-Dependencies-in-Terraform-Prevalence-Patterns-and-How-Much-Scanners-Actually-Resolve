"""
Phase 6c — Mapping the BOUNDARY of cross-file resolution in Checkov.

BACKGROUND (why this experiment exists):
Phase 6b tested the simplest cross-file construct — an insecure default in
variables.tf consumed by main.tf — and found that Checkov RESOLVES it: the
treatment run reproduced the inline run exactly (CKV_AWS_20 fired in both).
The blanket claim "single-file scanners cannot follow cross-file references" is
therefore FALSE for that construct and must not be made.

The scientifically useful question is narrower and harder:
    For WHICH cross-file constructs does resolution succeed, and where does it break?

DESIGN:
For each construct we build a matched triple of repositories:
    CONTROL    — same structure, SECURE value
    TREATMENT  — same structure, INSECURE value delivered via the construct
    INLINE     — the INSECURE value written directly, no indirection (positive control)

Decision rule per construct:
    treatment == inline  and  treatment != control  -> RESOLVED   (tool follows it)
    treatment == control and  inline  != control    -> NOT RESOLVED (blind spot here)
    inline == control                               -> INCONCLUSIVE (no rule fires at all)

Output: a table of constructs x verdict. That table is the contribution: an empirical
map of where state-of-the-art IaC scanning stops following cross-file structure.
"""
import os, subprocess, json, shutil

WORK = "/content/checkov_boundary" if os.path.isdir("/content") else "./checkov_boundary"
os.makedirs(WORK, exist_ok=True)

SECURE   = "private"
INSECURE = "public-read"

def sh(cmd, timeout=900):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

def checkov(path):
    """Return set of (check_id, resource) failed checks."""
    r = sh(["checkov","-d",path,"-o","json","--compact","--quiet"])
    out = r.stdout.strip()
    if not out:
        return set()
    try:
        res = json.loads(out)
    except Exception:
        return set()
    blocks = res if isinstance(res, list) else [res]
    pairs = set()
    for b in blocks:
        for f in b.get("results",{}).get("failed_checks",[]):
            pairs.add((f.get("check_id"), f.get("resource")))
    return pairs

def w(path, rel, text):
    full = os.path.join(path, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    open(full,"w").write(text)

def fresh(name):
    d = os.path.join(WORK, name)
    shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    return d

BUCKET = ('resource "aws_s3_bucket" "data" {\n  bucket = "example-data-bucket"\n}\n\n')

# ----------------------------------------------------------------------
# Construct builders. Each returns a directory with the given acl value
# delivered through a specific cross-file mechanism.
# ----------------------------------------------------------------------

def c_inline(name, val):
    """Positive control: literal in the same file."""
    d = fresh(name)
    w(d,"main.tf", BUCKET +
      'resource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n'
      f'  acl    = "{val}"\n' '}\n')
    return d

def c_var_default(name, val):
    """C1: variable default in a separate file (Phase 6b showed this resolves)."""
    d = fresh(name)
    w(d,"variables.tf", f'variable "bucket_acl" {{\n  type = string\n  default = "{val}"\n}}\n')
    w(d,"main.tf", BUCKET +
      'resource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n'
      '  acl    = var.bucket_acl\n}\n')
    return d

def c_locals(name, val):
    """C2: value routed through a local in a separate file."""
    d = fresh(name)
    w(d,"locals.tf", f'locals {{\n  effective_acl = "{val}"\n}}\n')
    w(d,"main.tf", BUCKET +
      'resource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n'
      '  acl    = local.effective_acl\n}\n')
    return d

def c_tfvars(name, val):
    """C3: variable declared with a SECURE default but overridden in terraform.tfvars."""
    d = fresh(name)
    w(d,"variables.tf", f'variable "bucket_acl" {{\n  type = string\n  default = "{SECURE}"\n}}\n')
    w(d,"terraform.tfvars", f'bucket_acl = "{val}"\n')
    w(d,"main.tf", BUCKET +
      'resource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n'
      '  acl    = var.bucket_acl\n}\n')
    return d

def c_module_input(name, val):
    """C4: root passes the value INTO a local module that creates the resource."""
    d = fresh(name)
    w(d,"main.tf",
      'module "storage" {\n  source     = "./modules/storage"\n'
      f'  bucket_acl = "{val}"\n' '}\n')
    w(d,"modules/storage/variables.tf",
      'variable "bucket_acl" {\n  type = string\n  default = "private"\n}\n')
    w(d,"modules/storage/main.tf", BUCKET +
      'resource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n'
      '  acl    = var.bucket_acl\n}\n')
    return d

def c_module_chain(name, val):
    """C5: module A exposes the value as an output; module B consumes it."""
    d = fresh(name)
    w(d,"main.tf",
      'module "cfg" {\n  source = "./modules/cfg"\n'
      f'  acl_in = "{val}"\n' '}\n\n'
      'module "storage" {\n  source     = "./modules/storage"\n'
      '  bucket_acl = module.cfg.acl_out\n}\n')
    w(d,"modules/cfg/variables.tf", 'variable "acl_in" {\n  type = string\n}\n')
    w(d,"modules/cfg/outputs.tf",   'output "acl_out" {\n  value = var.acl_in\n}\n')
    w(d,"modules/storage/variables.tf",
      'variable "bucket_acl" {\n  type = string\n  default = "private"\n}\n')
    w(d,"modules/storage/main.tf", BUCKET +
      'resource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n'
      '  acl    = var.bucket_acl\n}\n')
    return d

def c_nested_module(name, val):
    """C6: two levels of module nesting before the resource is created."""
    d = fresh(name)
    w(d,"main.tf",
      'module "outer" {\n  source = "./modules/outer"\n'
      f'  bucket_acl = "{val}"\n' '}\n')
    w(d,"modules/outer/variables.tf",'variable "bucket_acl" {\n  type = string\n}\n')
    w(d,"modules/outer/main.tf",
      'module "inner" {\n  source     = "./inner"\n  bucket_acl = var.bucket_acl\n}\n')
    w(d,"modules/outer/inner/variables.tf",
      'variable "bucket_acl" {\n  type = string\n  default = "private"\n}\n')
    w(d,"modules/outer/inner/main.tf", BUCKET +
      'resource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n'
      '  acl    = var.bucket_acl\n}\n')
    return d

def c_override(name, val):
    """C7: Terraform override.tf semantics - a later file replaces an earlier value."""
    d = fresh(name)
    w(d,"main.tf", BUCKET +
      'resource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n'
      f'  acl    = "{SECURE}"\n' '}\n')
    w(d,"override.tf",
      'resource "aws_s3_bucket_acl" "data" {\n'
      f'  acl = "{val}"\n' '}\n')
    return d

CONSTRUCTS = [
    ("C1 variable default (separate file)", c_var_default),
    ("C2 local value (separate file)",      c_locals),
    ("C3 terraform.tfvars override",        c_tfvars),
    ("C4 module input (local module)",      c_module_input),
    ("C5 module output chaining",           c_module_chain),
    ("C6 nested module (2 levels)",         c_nested_module),
    ("C7 override.tf (last-wins)",          c_override),
]

def verdict(control, treatment, inline):
    if inline == control:
        return "INCONCLUSIVE (no rule fires even inline)"
    if treatment != control and treatment == inline:
        return "RESOLVED (tool follows the construct)"
    if treatment == control:
        return "NOT RESOLVED (blind spot)"
    return "PARTIAL (differs from both)"

def main():
    if shutil.which("checkov") is None:
        print("Installing checkov ..."); sh(["pip","install","-q","checkov"], timeout=1800)

    print("="*78)
    print("PHASE 6c — where does Checkov stop following cross-file structure?")
    print("="*78)

    # inline positive control is construct-independent
    inline_secure   = checkov(c_inline("inline_secure",   SECURE))
    inline_insecure = checkov(c_inline("inline_insecure", INSECURE))
    inline_delta = inline_insecure - inline_secure
    print(f"\nInline positive control: {len(inline_secure)} vs {len(inline_insecure)} findings")
    print(f"  delta (the check that detects the insecure value): "
          f"{sorted(inline_delta) if inline_delta else 'NONE — rule never fires!'}")
    if not inline_delta:
        print("  [!] Without an inline delta no construct can be judged. Stopping.")
        return

    rows = []
    for label, builder in CONSTRUCTS:
        safe = label.split()[0]
        ctrl  = checkov(builder(f"{safe}_control",   SECURE))
        treat = checkov(builder(f"{safe}_treatment", INSECURE))
        v = verdict(ctrl, treat, inline_insecure)
        delta = sorted(treat - ctrl)
        rows.append({"construct":label,"control":len(ctrl),"treatment":len(treat),
                     "delta":[list(x) for x in delta],"verdict":v})
        print(f"\n{label}")
        print(f"   control={len(ctrl)} treatment={len(treat)}  delta={delta if delta else '[]'}")
        print(f"   => {v}")

    print("\n" + "="*78)
    print("SUMMARY TABLE (for the paper)")
    print("="*78)
    print(f"{'Construct':40s} {'Verdict'}")
    print("-"*78)
    for r in rows:
        print(f"{r['construct']:40s} {r['verdict']}")

    json.dump({"inline_delta":[list(x) for x in sorted(inline_delta)],"constructs":rows},
              open(os.path.join(WORK,"boundary_results.json"),"w"), indent=2)
    print(f"\nSaved boundary_results.json to {WORK}")
    print("\nHOW TO REPORT THIS:")
    print("  Constructs marked RESOLVED are followed by the tool - do NOT claim a blind")
    print("  spot for them. Constructs marked NOT RESOLVED are the genuine gap, and are")
    print("  the precise, defensible contribution of this experiment.")

if __name__ == "__main__":
    main()
