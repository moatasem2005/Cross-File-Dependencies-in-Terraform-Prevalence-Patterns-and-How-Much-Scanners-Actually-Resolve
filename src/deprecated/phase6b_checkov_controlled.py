"""
Phase 6b — CORRECTED Checkov cross-file experiment.

WHY THIS REPLACES PHASE 6:
The first version asked "does Checkov report an ACL finding?" and filtered findings
by the substring 'acl'. That filter was wrong: Checkov's public-read check is
CKV_AWS_20, whose id contains no 'acl' substring, so the script reported 0 when the
check had in fact fired. Concluding "Checkov missed it" from that output would have
been incorrect.

THE CORRECT DESIGN — control vs treatment:
Build two repositories that are byte-identical except for ONE thing: the default
value of a variable in variables.tf that main.tf consumes.

    CONTROL   : variable "bucket_acl" default = "private"       (secure)
    TREATMENT : variable "bucket_acl" default = "public-read"   (insecure)

Then:
  - If Checkov RESOLVES the cross-file variable, the two runs must differ
    (the insecure one should raise a public-access finding the secure one does not).
  - If the two runs are IDENTICAL, Checkov is not using the cross-file value at all:
    its verdict is independent of whether the configuration is actually insecure.
    That is the blind spot, demonstrated with ground truth.

We report the exact set difference of check_ids, so the conclusion follows from the
data rather than from a substring heuristic.
"""
import os, subprocess, json, shutil

WORK = "/content/checkov_exp2" if os.path.isdir("/content") else "./checkov_exp2"
os.makedirs(WORK, exist_ok=True)

def sh(cmd, timeout=900):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

def run_checkov(path):
    """Return the set of (check_id, resource) pairs Checkov fails on."""
    r = sh(["checkov","-d",path,"-o","json","--compact","--quiet"])
    out = r.stdout.strip()
    if not out:
        print("   [warn] no checkov output:", r.stderr[:200]); return set(), []
    try:
        res = json.loads(out)
    except Exception as e:
        print("   [warn] json parse failed:", e); return set(), []
    blocks = res if isinstance(res, list) else [res]
    pairs, detail = set(), []
    for b in blocks:
        for f in b.get("results",{}).get("failed_checks",[]):
            cid = f.get("check_id"); rsc = f.get("resource")
            pairs.add((cid, rsc))
            detail.append({"check_id":cid,"resource":rsc,"name":f.get("check_name"),
                           "file":f.get("file_path")})
    return pairs, detail

MAIN_TF = (
 'resource "aws_s3_bucket" "data" {\n'
 '  bucket = "example-data-bucket"\n'
 '}\n\n'
 'resource "aws_s3_bucket_acl" "data" {\n'
 '  bucket = aws_s3_bucket.data.id\n'
 '  acl    = var.bucket_acl\n'
 '}\n'
)
def variables_tf(default_value):
    return f'variable "bucket_acl" {{\n  type    = string\n  default = "{default_value}"\n}}\n'

def build_variant(name, default_value):
    d = os.path.join(WORK, name)
    shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    open(os.path.join(d,"main.tf"),"w").write(MAIN_TF)
    open(os.path.join(d,"variables.tf"),"w").write(variables_tf(default_value))
    return d

def build_inline_variant(name, literal_value):
    """Same insecure value, but written INLINE in main.tf (no cross-file indirection).
    This is the positive control: if Checkov can detect the issue at all, it must
    detect it here. It separates 'cannot detect this issue' from 'cannot follow the
    cross-file reference'."""
    d = os.path.join(WORK, name)
    shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    open(os.path.join(d,"main.tf"),"w").write(
        'resource "aws_s3_bucket" "data" {\n  bucket = "example-data-bucket"\n}\n\n'
        'resource "aws_s3_bucket_acl" "data" {\n'
        '  bucket = aws_s3_bucket.data.id\n'
        f'  acl    = "{literal_value}"\n'
        '}\n')
    return d

def main():
    if shutil.which("checkov") is None:
        print("Installing checkov ..."); sh(["pip","install","-q","checkov"], timeout=1800)

    print("="*70)
    print("CORRECTED EXPERIMENT — does Checkov resolve a cross-file variable value?")
    print("="*70)

    ctrl = build_variant("control_secure",   "private")
    treat= build_variant("treatment_insecure","public-read")
    inline_bad = build_inline_variant("inline_insecure","public-read")

    print("\n[1] CONTROL   (cross-file, default = private)")
    c_pairs, c_detail = run_checkov(ctrl)
    print(f"    findings: {len(c_pairs)}")

    print("\n[2] TREATMENT (cross-file, default = public-read)")
    t_pairs, t_detail = run_checkov(treat)
    print(f"    findings: {len(t_pairs)}")

    print("\n[3] POSITIVE CONTROL (inline literal = public-read, no cross-file)")
    i_pairs, i_detail = run_checkov(inline_bad)
    print(f"    findings: {len(i_pairs)}")

    only_treat = t_pairs - c_pairs
    only_ctrl  = c_pairs - t_pairs
    only_inline= i_pairs - c_pairs

    print("\n" + "-"*70)
    print("RESULT 1 — cross-file sensitivity (treatment vs control):")
    print(f"  findings ONLY in the insecure cross-file variant: {len(only_treat)}")
    for cid,rsc in sorted(only_treat): print(f"     + {cid}  {rsc}")
    print(f"  findings ONLY in the secure variant: {len(only_ctrl)}")
    for cid,rsc in sorted(only_ctrl): print(f"     - {cid}  {rsc}")
    if not only_treat and not only_ctrl:
        print("  => IDENTICAL. Checkov's verdict does NOT change when the cross-file")
        print("     value flips from secure to insecure: it is not resolving the")
        print("     variable across files. This is the blind spot, with ground truth.")
    else:
        print("  => DIFFERENT. Checkov IS sensitive to the cross-file value here;")
        print("     the blind-spot claim is NOT supported for this construct.")

    print("\nRESULT 2 — can Checkov detect the issue at all (inline positive control)?")
    print(f"  findings ONLY in the inline-insecure variant vs control: {len(only_inline)}")
    for cid,rsc in sorted(only_inline): print(f"     + {cid}  {rsc}")
    if only_inline and not only_treat:
        print("  => Checkov detects the insecure ACL when written INLINE, but not when")
        print("     the same value arrives through a cross-file variable. This isolates")
        print("     the failure to the cross-file indirection, not to a missing rule.")
    elif not only_inline:
        print("  => Checkov does not flag this even inline; the construct is outside its")
        print("     rule set, so it cannot be used to demonstrate a cross-file blind spot.")

    out = {"control":sorted(map(list,c_pairs)), "treatment":sorted(map(list,t_pairs)),
           "inline":sorted(map(list,i_pairs)),
           "only_in_treatment":sorted(map(list,only_treat)),
           "only_in_inline":sorted(map(list,only_inline))}
    json.dump(out, open(os.path.join(WORK,"corrected_results.json"),"w"), indent=2)
    print(f"\nSaved corrected_results.json to {WORK}")
    print("\nReport in the paper whichever of the two outcomes actually occurs.")

if __name__ == "__main__":
    main()
