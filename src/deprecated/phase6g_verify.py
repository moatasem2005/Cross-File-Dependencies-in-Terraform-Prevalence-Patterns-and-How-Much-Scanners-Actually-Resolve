"""
Phase 6g — VERIFY the cross-tool difference (rule out config artefacts).

Phase 6f found Checkov resolves nearly all cross-file constructs while tfsec,
terrascan, and trivy resolve only same-scope locals. Before reporting that, we must
rule out the mundane explanation that the other tools simply needed different flags,
directory handling, or a proper probe. This script hardens the experiment:

  1. FLAGS: each tool is invoked the way its docs intend for a directory scan,
     including recursive/module handling where a flag exists.
  2. ENCRYPTION PROBE (P3) REDESIGNED: insecurity is now the ABSENCE of an encryption
     block (the standard misconfiguration), controlled via a cross-file boolean that
     decides whether the SSE resource is created — using count. This gives every tool
     a real signal (they all flag unencrypted S3), so P3 becomes informative.
  3. SANITY: for each tool we assert the inline positive control fires the signal for
     every property; if it does not, the tool cannot be judged for that property and
     is marked N/A rather than NOT-RES (avoids false blind-spot claims).

Interpretation rule is unchanged (control/treatment/inline).
"""
import os, subprocess, json, shutil, re

WORK="/content/rq4_verify" if os.path.isdir("/content") else "./rq4_verify"
os.makedirs(WORK, exist_ok=True)

def sh(cmd, timeout=1800):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
def w(path, rel, text):
    full=os.path.join(path,rel); os.makedirs(os.path.dirname(full),exist_ok=True); open(full,"w").write(text)
def fresh(name):
    d=os.path.join(WORK,name); shutil.rmtree(d,ignore_errors=True); os.makedirs(d); return d

# ------------------------------------------------- tool runners (restored from Phase 6f — these read output correctly)
def ids_checkov(p):
    if not shutil.which("checkov"): return None
    r=sh(["checkov","-d",p,"-o","json","--compact","--quiet"])
    o=r.stdout.strip()
    if not o: return set()
    try: res=json.loads(o)
    except: return set()
    B=res if isinstance(res,list) else [res]; ids=set()
    for b in B:
        for f in b.get("results",{}).get("failed_checks",[]): ids.add(f.get("check_id"))
    return ids

def ids_tfsec(p):
    if not shutil.which("tfsec"): return None
    r=sh(["tfsec",p,"-f","json","--no-colour","--soft-fail"])
    o=r.stdout.strip(); m=re.search(r"\{.*\}",o,re.S); o=m.group(0) if m else ""
    if not o: return set()
    try: res=json.loads(o)
    except: return set()
    return {x.get("long_id") or x.get("rule_id") for x in (res.get("results") or [])}

def ids_terrascan(p):
    if not shutil.which("terrascan"): return None
    r=sh(["terrascan","scan","-i","terraform","-d",p,"-o","json"])
    o=r.stdout.strip(); m=re.search(r"\{.*\}",o,re.S); o=m.group(0) if m else ""
    if not o: return set()
    try: res=json.loads(o)
    except: return set()
    v=res.get("results",{}).get("violations") or []
    return {x.get("rule_id") for x in v}

def ids_trivy(p):
    if not shutil.which("trivy"): return None
    r=sh(["trivy","config","-f","json","-q",p])
    o=r.stdout.strip()
    if not o: return set()
    try: res=json.loads(o)
    except: return set()
    ids=set()
    for result in (res.get("Results") or []):
        for m in (result.get("Misconfigurations") or []):
            ids.add(m.get("ID"))
    return ids

TOOLS={"checkov":ids_checkov,"tfsec":ids_tfsec,"terrascan":ids_terrascan,"trivy":ids_trivy}

# ------------------------------------------------- properties
def res_acl(v):
    return ('resource "aws_s3_bucket" "b" { bucket = "ex" }\n'
            'resource "aws_s3_bucket_acl" "b" { bucket = aws_s3_bucket.b.id\n'
            f'  acl = {v} }}\n')
def res_sg(v):
    return ('resource "aws_security_group" "b" {\n'
            '  name = "ex"\n'
            '  ingress {\n'
            '    from_port   = 22\n'
            '    to_port     = 22\n'
            '    protocol    = "tcp"\n'
            f'    cidr_blocks = {v}\n'
            '  }\n'
            '}\n')
def res_enc(create_expr):
    # insecurity = NO encryption resource. create_expr is a count (1 secure / 0 insecure).
    return ('resource "aws_s3_bucket" "b" {\n'
            '  bucket = "ex"\n'
            '}\n'
            'resource "aws_s3_bucket_server_side_encryption_configuration" "b" {\n'
            f'  count  = {create_expr}\n'
            '  bucket = aws_s3_bucket.b.id\n'
            '  rule {\n'
            '    apply_server_side_encryption_by_default {\n'
            '      sse_algorithm = "AES256"\n'
            '    }\n'
            '  }\n'
            '}\n')

PROPS={
 "P1_acl":{"res":res_acl,"sec":'"private"',"ins":'"public-read"',"vt":"string"},
 "P2_sg":{"res":res_sg,"sec":'["10.0.0.0/16"]',"ins":'["0.0.0.0/0"]',"vt":"list(string)"},
 "P3_enc":{"res":res_enc,"sec":'1',"ins":'0',"vt":"number"},   # count: 1 creates SSE (secure), 0 omits (insecure)
}

# ------------------------------------------------- construct builders (value-generic)
def inline(prop,name,val): 
    d=fresh(name); w(d,"main.tf",PROPS[prop]["res"](val)); return d
def var_default(prop,name,val):
    d=fresh(name); w(d,"variables.tf",f'variable "v" {{ type={PROPS[prop]["vt"]}\n default={val} }}\n')
    w(d,"main.tf",PROPS[prop]["res"]("var.v")); return d
def locals_(prop,name,val):
    d=fresh(name); w(d,"locals.tf",f'locals {{ v={val} }}\n'); w(d,"main.tf",PROPS[prop]["res"]("local.v")); return d
def tfvars(prop,name,val):
    d=fresh(name); w(d,"variables.tf",f'variable "v" {{ type={PROPS[prop]["vt"]}\n default={PROPS[prop]["sec"]} }}\n')
    w(d,"terraform.tfvars",f'v = {val}\n'); w(d,"main.tf",PROPS[prop]["res"]("var.v")); return d
def module_input(prop,name,val):
    d=fresh(name); w(d,"main.tf",'module "m" { source="./modules/m"\n'+f' v={val} }}\n')
    w(d,"modules/m/variables.tf",f'variable "v" {{ type={PROPS[prop]["vt"]} }}\n')
    w(d,"modules/m/main.tf",PROPS[prop]["res"]("var.v")); return d
def module_chain(prop,name,val):
    d=fresh(name); vt=PROPS[prop]["vt"]
    w(d,"main.tf",'module "cfg" { source="./modules/cfg"\n'+f' vin={val} }}\n\nmodule "m" {{ source="./modules/m"\n v=module.cfg.vout }}\n')
    w(d,"modules/cfg/variables.tf",f'variable "vin" {{ type={vt} }}\n')
    w(d,"modules/cfg/outputs.tf",'output "vout" { value=var.vin }\n')
    w(d,"modules/m/variables.tf",f'variable "v" {{ type={vt} }}\n')
    w(d,"modules/m/main.tf",PROPS[prop]["res"]("var.v")); return d
def nested(prop,name,val):
    d=fresh(name); vt=PROPS[prop]["vt"]
    w(d,"main.tf",'module "outer" { source="./modules/outer"\n'+f' v={val} }}\n')
    w(d,"modules/outer/variables.tf",f'variable "v" {{ type={vt} }}\n')
    w(d,"modules/outer/main.tf",'module "inner" { source="./inner"\n v=var.v }\n')
    w(d,"modules/outer/inner/variables.tf",f'variable "v" {{ type={vt} }}\n')
    w(d,"modules/outer/inner/main.tf",PROPS[prop]["res"]("var.v")); return d
def override(prop,name,val):
    d=fresh(name); w(d,"main.tf",PROPS[prop]["res"](PROPS[prop]["sec"]))
    if prop=="P1_acl":
        w(d,"override.tf",f'resource "aws_s3_bucket_acl" "b" {{ acl={val} }}\n')
    elif prop=="P2_sg":
        w(d,"override.tf",'resource "aws_security_group" "b" {\n'
          '  ingress {\n'
          '    from_port   = 22\n'
          '    to_port     = 22\n'
          '    protocol    = "tcp"\n'
          f'    cidr_blocks = {val}\n'
          '  }\n'
          '}\n')
    else:
        w(d,"override.tf",f'resource "aws_s3_bucket_server_side_encryption_configuration" "b" {{ count={val} }}\n')
    return d

CONSTRUCTS=[("C1 variable default",var_default),("C2 local value",locals_),
            ("C3 terraform.tfvars",tfvars),("C4 module input",module_input),
            ("C5 module output chaining",module_chain),("C6 nested module (2 levels)",nested),
            ("C7 override.tf",override)]

def verdict(sig,c,t):
    if sig is None: return "N/A"
    if not sig:     return "N/A(nosig)"
    if sig.issubset(t) and not sig.issubset(c): return "RESOLVED"
    if sig.isdisjoint(t-c): return "NOT-RES"
    return "PARTIAL"

def main():
    avail={t:shutil.which(t) is not None for t in TOOLS}
    print("tool availability:",avail)
    all_results={}
    for prop in PROPS:
        sec,ins=PROPS[prop]["sec"],PROPS[prop]["ins"]
        sig={}
        for tn,run in TOOLS.items():
            si=run(inline(prop,f"{prop}_{tn}_inl_i",ins)); ss=run(inline(prop,f"{prop}_{tn}_inl_s",sec))
            sig[tn]=None if si is None else (si-ss)
        print(f"\n### {prop}  signals:")
        for tn in TOOLS: print(f"   {tn}: {sorted(sig[tn]) if sig[tn] else sig[tn]}")
        all_results[prop]={}
        for tn,run in TOOLS.items():
            all_results[prop][tn]={}
            for label,b in CONSTRUCTS:
                tag=label.split()[0]
                if not sig.get(tn): all_results[prop][tn][label]="N/A"; continue
                c=run(b(prop,f"{prop}_{tn}_{tag}_c",sec)); t=run(b(prop,f"{prop}_{tn}_{tag}_t",ins))
                all_results[prop][tn][label]=verdict(sig[tn],c,t)
    tools=[t for t in TOOLS if avail[t]]
    for prop in PROPS:
        print("\n"+"="*84); print(f"MATRIX — {prop}"); print("="*84)
        print(f"{'Construct':30s} "+" ".join(f"{t:>10s}" for t in tools))
        print("-"*84)
        for label,_ in CONSTRUCTS:
            print(f"{label:30s} "+" ".join(f"{all_results[prop][t].get(label,'N/A'):>10s}" for t in tools))
    json.dump(all_results,open(os.path.join(WORK,"rq4_verified.json"),"w"),indent=2)
    print(f"\nSaved rq4_verified.json to {WORK}")
    # cross-tool summary per construct (how many tools resolve it, on P1/P2)
    print("\n"+"="*84); print("CROSS-TOOL SUMMARY (P1+P2, resolved count / available tools)"); print("="*84)
    for label,_ in CONSTRUCTS:
        cnt=0; tot=0
        for prop in ["P1_acl","P2_sg"]:
            for t in tools:
                v=all_results[prop][t].get(label)
                if v in ("RESOLVED","NOT-RES"): tot+=1
                if v=="RESOLVED": cnt+=1
        print(f"  {label:30s} {cnt}/{tot} resolved")

if __name__=="__main__":
    main()
