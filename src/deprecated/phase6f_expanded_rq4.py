"""
Phase 6f — EXPANDED RQ4: multiple tools x multiple security checks x 7 constructs.

Addresses the two generalisability concerns:
  (1) more tools : Checkov, tfsec, Terrascan, Trivy  (KICS optional)
  (2) more checks : not just S3 public-read ACL, but three independent
                    security properties delivered through the cross-file construct:
        P1  S3 public-read ACL              (acl = "public-read")
        P2  Security-group open ingress     (cidr_blocks = ["0.0.0.0/0"])
        P3  Unencrypted S3 bucket           (server-side encryption absent/disabled)

For each (tool, property, construct) we run the control/treatment/inline design and
record RESOLVED / NOT RESOLVED / INCONCLUSIVE. The output is a three-way matrix, which
is far stronger evidence of generalisability than a single ACL probe on one tool.
Each tool's signal check per property is DISCOVERED from its own inline control.
"""
import os, subprocess, json, shutil, glob, re

WORK = "/content/rq4_expanded" if os.path.isdir("/content") else "./rq4_expanded"
os.makedirs(WORK, exist_ok=True)

def sh(cmd, timeout=1800, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)

def w(path, rel, text):
    full=os.path.join(path,rel); os.makedirs(os.path.dirname(full),exist_ok=True)
    open(full,"w").write(text)
def fresh(name):
    d=os.path.join(WORK,name); shutil.rmtree(d,ignore_errors=True); os.makedirs(d); return d

# ---------------------------------------------------------------- resource templates
# Each property defines: the resource block (parametrised by an injected value),
# a SECURE value, and an INSECURE value.

def res_acl(val):
    return ('resource "aws_s3_bucket" "b" { bucket = "ex-bucket" }\n'
            'resource "aws_s3_bucket_acl" "b" {\n'
            '  bucket = aws_s3_bucket.b.id\n'
            f'  acl    = {val}\n'
            '}\n')

def res_sg(val):
    return ('resource "aws_security_group" "b" {\n'
            '  name = "ex-sg"\n'
            '  ingress {\n'
            '    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n'
            f'    cidr_blocks = {val}\n'
            '  }\n}\n')

def res_enc(val):
    # val is the SSE status string; "AES256" secure, "" -> no encryption block (insecure)
    return ('resource "aws_s3_bucket" "b" { bucket = "ex-bucket" }\n'
            'resource "aws_s3_bucket_server_side_encryption_configuration" "b" {\n'
            '  bucket = aws_s3_bucket.b.id\n'
            '  rule {\n'
            '    apply_server_side_encryption_by_default {\n'
            f'      sse_algorithm = {val}\n'
            '    }\n  }\n}\n')

PROPS = {
    "P1_s3_public_acl": {
        "res": res_acl,
        "secure": '"private"',   "insecure": '"public-read"',
        "var_type": "string",
    },
    "P2_sg_open_ingress": {
        "res": res_sg,
        "secure": '["10.0.0.0/16"]', "insecure": '["0.0.0.0/0"]',
        "var_type": "list(string)",
    },
    "P3_s3_unencrypted": {
        "res": res_enc,
        "secure": '"AES256"',    "insecure": '"aws:kms"',  # both valid; used only to test flow parity
        "var_type": "string",
    },
}
# NOTE on P3: both AES256 and aws:kms are "encrypted"; P3 mainly tests whether the tool
# follows the cross-file value into the SSE block at all (flow parity), reported as
# RESOLVED if treatment == inline. Property-level insecurity for encryption is better
# captured by ABSENCE, which single-file tools already flag; we keep P3 as a flow probe.

# ---------------------------------------------------------------- construct builders
# Each returns a repo dir; `emit(val_expr)` places the resource with the given value
# expression; the cross-file mechanism supplies that value.

def build_inline(prop, name, value_literal):
    d=fresh(name); w(d,"main.tf", PROPS[prop]["res"](value_literal)); return d

def build_var_default(prop, name, value_literal):
    d=fresh(name); vt=PROPS[prop]["var_type"]
    w(d,"variables.tf", f'variable "v" {{ type = {vt}\n  default = {value_literal} }}\n')
    w(d,"main.tf", PROPS[prop]["res"]("var.v")); return d

def build_locals(prop, name, value_literal):
    d=fresh(name)
    w(d,"locals.tf", f'locals {{ v = {value_literal} }}\n')
    w(d,"main.tf", PROPS[prop]["res"]("local.v")); return d

def build_tfvars(prop, name, value_literal):
    d=fresh(name); vt=PROPS[prop]["var_type"]; sec=PROPS[prop]["secure"]
    w(d,"variables.tf", f'variable "v" {{ type = {vt}\n  default = {sec} }}\n')
    w(d,"terraform.tfvars", f'v = {value_literal}\n')
    w(d,"main.tf", PROPS[prop]["res"]("var.v")); return d

def build_module_input(prop, name, value_literal):
    d=fresh(name); vt=PROPS[prop]["var_type"]
    w(d,"main.tf", 'module "m" { source = "./modules/m"\n'+f'  v = {value_literal} }}\n')
    w(d,"modules/m/variables.tf", f'variable "v" {{ type = {vt} }}\n')
    w(d,"modules/m/main.tf", PROPS[prop]["res"]("var.v")); return d

def build_module_chain(prop, name, value_literal):
    d=fresh(name); vt=PROPS[prop]["var_type"]
    w(d,"main.tf",
      'module "cfg" { source = "./modules/cfg"\n'+f'  vin = {value_literal} }}\n\n'
      'module "m" { source = "./modules/m"\n  v = module.cfg.vout }\n')
    w(d,"modules/cfg/variables.tf", f'variable "vin" {{ type = {vt} }}\n')
    w(d,"modules/cfg/outputs.tf", 'output "vout" { value = var.vin }\n')
    w(d,"modules/m/variables.tf", f'variable "v" {{ type = {vt} }}\n')
    w(d,"modules/m/main.tf", PROPS[prop]["res"]("var.v")); return d

def build_nested(prop, name, value_literal):
    d=fresh(name); vt=PROPS[prop]["var_type"]
    w(d,"main.tf", 'module "outer" { source = "./modules/outer"\n'+f'  v = {value_literal} }}\n')
    w(d,"modules/outer/variables.tf", f'variable "v" {{ type = {vt} }}\n')
    w(d,"modules/outer/main.tf", 'module "inner" { source = "./inner"\n  v = var.v }\n')
    w(d,"modules/outer/inner/variables.tf", f'variable "v" {{ type = {vt} }}\n')
    w(d,"modules/outer/inner/main.tf", PROPS[prop]["res"]("var.v")); return d

def build_override(prop, name, value_literal):
    d=fresh(name); sec=PROPS[prop]["secure"]
    w(d,"main.tf", PROPS[prop]["res"](sec))
    # override the whole resource's value via a second file (last-wins)
    # For simplicity we override the ACL / cidr / sse via a resource block of the same address.
    if prop=="P1_s3_public_acl":
        w(d,"override.tf", 'resource "aws_s3_bucket_acl" "b" {\n'+f'  acl = {value_literal}\n'+'}\n')
    elif prop=="P2_sg_open_ingress":
        w(d,"override.tf", 'resource "aws_security_group" "b" {\n  ingress {\n'
          '    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n'
          f'    cidr_blocks = {value_literal}\n'+'  }\n}\n')
    else:
        w(d,"override.tf", 'resource "aws_s3_bucket_server_side_encryption_configuration" "b" {\n'
          '  rule { apply_server_side_encryption_by_default {\n'
          f'    sse_algorithm = {value_literal}\n'+'  } }\n}\n')
    return d

CONSTRUCTS=[("C1 variable default",build_var_default),
            ("C2 local value",build_locals),
            ("C3 terraform.tfvars",build_tfvars),
            ("C4 module input",build_module_input),
            ("C5 module output chaining",build_module_chain),
            ("C6 nested module (2 levels)",build_nested),
            ("C7 override.tf",build_override)]

# ---------------------------------------------------------------- tool runners (id sets)
MODULE_PREFIX = re.compile(r"^(?:module\.[A-Za-z0-9_-]+\.)+")

def ids_checkov(path):
    if not shutil.which("checkov"): return None
    r=sh(["checkov","-d",path,"-o","json","--compact","--quiet"])
    out=r.stdout.strip()
    if not out: return set()
    try: res=json.loads(out)
    except Exception: return set()
    blocks=res if isinstance(res,list) else [res]
    ids=set()
    for b in blocks:
        for f in b.get("results",{}).get("failed_checks",[]): ids.add(f.get("check_id"))
    return ids

def ids_tfsec(path):
    if not shutil.which("tfsec"): return None
    r=sh(["tfsec",path,"-f","json","--no-colour","--soft-fail"])
    out=r.stdout.strip(); m=re.search(r"\{.*\}",out,re.S); out=m.group(0) if m else ""
    if not out: return set()
    try: res=json.loads(out)
    except Exception: return set()
    return {x.get("long_id") or x.get("rule_id") for x in (res.get("results") or [])}

def ids_terrascan(path):
    if not shutil.which("terrascan"): return None
    r=sh(["terrascan","scan","-i","terraform","-d",path,"-o","json"])
    out=r.stdout.strip(); m=re.search(r"\{.*\}",out,re.S); out=m.group(0) if m else ""
    if not out: return set()
    try: res=json.loads(out)
    except Exception: return set()
    v=res.get("results",{}).get("violations") or []
    return {x.get("rule_id") for x in v}

def ids_trivy(path):
    if not shutil.which("trivy"): return None
    r=sh(["trivy","config","-f","json","-q",path])
    out=r.stdout.strip(); 
    if not out: return set()
    try: res=json.loads(out)
    except Exception: return set()
    ids=set()
    for result in (res.get("Results") or []):
        for mis in (result.get("Misconfigurations") or []):
            ids.add(mis.get("ID"))
    return ids

TOOLS={"checkov":ids_checkov,"tfsec":ids_tfsec,"terrascan":ids_terrascan,"trivy":ids_trivy}

def verdict(signal, ctrl, treat):
    if signal is None: return "N/A"
    if not signal: return "INCONC"
    if signal.issubset(treat) and not signal.issubset(ctrl): return "RESOLVED"
    if signal.isdisjoint(treat-ctrl): return "NOT-RES"
    return "PARTIAL"

def main():
    avail={t:(shutil.which(t) is not None) for t in TOOLS}
    print("="*84); print("PHASE 6f — EXPANDED RQ4  (tools x checks x constructs)"); print("="*84)
    print("tool availability:", avail)

    results={}   # results[prop][tool][construct] = verdict
    for prop in PROPS:
        results[prop]={}
        insec=PROPS[prop]["insecure"]; sec=PROPS[prop]["secure"]
        # discover each tool's signal for THIS property from the inline control
        inl_s=build_inline(prop,f"{prop}_inl_sec",sec)
        inl_i=build_inline(prop,f"{prop}_inl_ins",insec)
        signals={}
        for tname,run in TOOLS.items():
            si=run(inl_i); ss=run(inl_s)
            signals[tname]=None if si is None else (si-ss)
        print(f"\n### Property {prop}")
        for tname in TOOLS:
            s=signals[tname]
            print(f"   [{tname}] signal: {sorted(s) if s else s}")
        for tname,run in TOOLS.items():
            results[prop][tname]={}
            for label,builder in CONSTRUCTS:
                tag=label.split()[0]
                if signals[tname] is None or not signals[tname]:
                    results[prop][tname][label]= "N/A" if signals[tname] is None else "INCONC"
                    continue
                c=run(builder(prop,f"{prop}_{tname}_{tag}_c",sec))
                t=run(builder(prop,f"{prop}_{tname}_{tag}_t",insec))
                results[prop][tname][label]=verdict(signals[tname],c,t)

    # print matrices
    tools=[t for t in TOOLS if avail[t]]
    for prop in PROPS:
        print("\n"+"="*84); print(f"MATRIX — {prop}"); print("="*84)
        print(f"{'Construct':30s} " + " ".join(f"{t:>10s}" for t in tools))
        print("-"*84)
        for label,_ in CONSTRUCTS:
            print(f"{label:30s} " + " ".join(f"{results[prop][t].get(label,'N/A'):>10s}" for t in tools))

    json.dump(results, open(os.path.join(WORK,"rq4_expanded_results.json"),"w"), indent=2)
    print(f"\nSaved rq4_expanded_results.json to {WORK}")
    print("\nREAD: a construct RESOLVED across tools AND across properties is robustly")
    print("resolved; a construct NOT-RES across tools/properties is a robust blind spot.")

if __name__=="__main__":
    main()
