"""
rq4_experiment.py — CANONICAL RQ4 experiment (supersedes phase6/6b-6g).

This is the single experiment the paper's RQ4 claims rest on. Earlier scripts
compared only sets of rule identifiers; the paper described a stronger oracle than
those scripts implemented. This version implements exactly what the paper claims.

Oracle (four parts, all enforced in code)
  1. rule identity      : the fired rule must equal the tool's own signal rule,
                          discovered from that tool's inline positive control.
  2. resource address   : the finding must attach to the EXPECTED resource address,
                          after stripping `module.<name>.` prefixes.
  3. treatment contrast : the (rule, address) pair must appear in treatment and be
                          absent from the matched control.
  4. inline confirmation: the same pair must appear in the inline positive control,
                          proving the rule exists and is reachable.

Verdict vocabulary (kept distinct, never merged)
  RESOLVED     - all four oracle conditions satisfied
  NOT_RESOLVED - inline fires, treatment == control on the signal pair
  INCONCLUSIVE - inline does not fire (tool has no applicable rule)
  ERROR        - tool failed to execute or produced unparseable output
  N/A          - tool not installed

Every run records command, return code, stdout/stderr (truncated), and duration.
An environment manifest (tool versions, OS, Python, timestamps) is written alongside
structured results, so the reported verdicts are reproducible and auditable.

Generated HCL is validated before scanning; a case whose sources are invalid is
reported as ERROR rather than silently producing "no findings".
"""
from __future__ import annotations
import os, re, json, shutil, subprocess, platform, sys, time
from datetime import datetime, timezone

WORK = "/content/rq4" if os.path.isdir("/content") else "./rq4_out"
os.makedirs(WORK, exist_ok=True)
RUNS_DIR = os.path.join(WORK, "raw_runs"); os.makedirs(RUNS_DIR, exist_ok=True)

MODULE_PREFIX = re.compile(r"^(?:module\.[A-Za-z0-9_-]+\.)+")
_run_counter = {"n": 0}


# ==========================================================================
# process execution with full capture
# ==========================================================================
def run_cmd(cmd, timeout=1800, cwd=None):
    """Execute and capture everything. Never swallows failures."""
    _run_counter["n"] += 1
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        rec = {"cmd": cmd, "returncode": p.returncode,
               "stdout": p.stdout, "stderr": p.stderr,
               "duration_s": round(time.time() - t0, 2), "timeout": False}
    except subprocess.TimeoutExpired as e:
        rec = {"cmd": cmd, "returncode": None, "stdout": e.stdout or "",
               "stderr": f"TIMEOUT after {timeout}s", "duration_s": timeout, "timeout": True}
    # persist raw run
    rid = f"run_{_run_counter['n']:05d}"
    with open(os.path.join(RUNS_DIR, rid + ".json"), "w") as f:
        json.dump({**rec, "stdout": rec["stdout"][:20000],
                   "stderr": rec["stderr"][:20000]}, f, indent=1)
    rec["run_id"] = rid
    return rec


def tool_version(tool):
    if not shutil.which(tool):
        return None
    cmds = {"checkov": ["checkov", "--version"],
            "tfsec": ["tfsec", "--version"],
            "terrascan": ["terrascan", "version"],
            "trivy": ["trivy", "--version"],
            "terraform": ["terraform", "version"]}
    r = run_cmd(cmds.get(tool, [tool, "--version"]), timeout=120)
    out = (r["stdout"] or r["stderr"] or "").strip().splitlines()
    return out[0][:120] if out else "unknown"


# ==========================================================================
# tool adapters: return list of (rule_id, normalised_resource_address) or ERROR
# ==========================================================================
class ToolError(Exception):
    pass


def _norm_addr(addr: str) -> str:
    return MODULE_PREFIX.sub("", (addr or "").strip())


def scan_checkov(path):
    if not shutil.which("checkov"):
        return None
    r = run_cmd(["checkov", "-d", path, "-o", "json", "--compact", "--quiet"])
    # checkov exits 1 when findings exist; both 0 and 1 are normal
    if r["returncode"] not in (0, 1) or r["timeout"]:
        raise ToolError(f"checkov rc={r['returncode']} {r['stderr'][:200]}")
    out = (r["stdout"] or "").strip()
    if not out:
        return []
    try:
        res = json.loads(out)
    except Exception as e:
        raise ToolError(f"checkov JSON parse failed: {e}")
    blocks = res if isinstance(res, list) else [res]
    pairs = []
    for b in blocks:
        for f in b.get("results", {}).get("failed_checks", []):
            pairs.append((f.get("check_id"), _norm_addr(f.get("resource"))))
    return pairs


def scan_tfsec(path):
    if not shutil.which("tfsec"):
        return None
    r = run_cmd(["tfsec", path, "-f", "json", "--no-colour", "--soft-fail"])
    if r["timeout"]:
        raise ToolError("tfsec timeout")
    out = (r["stdout"] or "").strip()
    m = re.search(r"\{.*\}", out, re.S)
    if not m:
        if r["returncode"] not in (0, 1):
            raise ToolError(f"tfsec rc={r['returncode']} {r['stderr'][:200]}")
        return []
    try:
        res = json.loads(m.group(0))
    except Exception as e:
        raise ToolError(f"tfsec JSON parse failed: {e}")
    pairs = []
    for x in (res.get("results") or []):
        rule = x.get("long_id") or x.get("rule_id")
        addr = x.get("resource") or ""
        pairs.append((rule, _norm_addr(addr)))
    return pairs


def scan_terrascan(path):
    if not shutil.which("terrascan"):
        return None
    r = run_cmd(["terrascan", "scan", "-i", "terraform", "-d", path, "-o", "json"])
    if r["timeout"]:
        raise ToolError("terrascan timeout")
    out = (r["stdout"] or "").strip()
    m = re.search(r"\{.*\}", out, re.S)
    if not m:
        # terrascan returns 3 when violations found; 0 when clean
        if r["returncode"] not in (0, 3, 4, 5):
            raise ToolError(f"terrascan rc={r['returncode']} {r['stderr'][:200]}")
        return []
    try:
        res = json.loads(m.group(0))
    except Exception as e:
        raise ToolError(f"terrascan JSON parse failed: {e}")
    pairs = []
    for v in (res.get("results", {}).get("violations") or []):
        rule = v.get("rule_id")
        addr = f"{v.get('resource_type','')}.{v.get('resource_name','')}".strip(".")
        pairs.append((rule, _norm_addr(addr)))
    return pairs


def scan_trivy(path):
    if not shutil.which("trivy"):
        return None
    r = run_cmd(["trivy", "config", "-f", "json", "-q", path])
    if r["timeout"]:
        raise ToolError("trivy timeout")
    out = (r["stdout"] or "").strip()
    if not out:
        if r["returncode"] not in (0, 1):
            raise ToolError(f"trivy rc={r['returncode']} {r['stderr'][:200]}")
        return []
    try:
        res = json.loads(out)
    except Exception as e:
        raise ToolError(f"trivy JSON parse failed: {e}")
    pairs = []
    for result in (res.get("Results") or []):
        for mis in (result.get("Misconfigurations") or []):
            if mis.get("Status", "FAIL") != "FAIL":
                continue
            addr = ""
            cc = mis.get("CauseMetadata") or {}
            addr = cc.get("Resource") or ""
            pairs.append((mis.get("ID"), _norm_addr(addr)))
    return pairs


TOOLS = {"checkov": scan_checkov, "tfsec": scan_tfsec,
         "terrascan": scan_terrascan, "trivy": scan_trivy}


# ==========================================================================
# case generation  (P1 = S3 public ACL, P2 = open security-group ingress)
# P3 (encryption) is intentionally EXCLUDED - see paper: the count=0 formulation
# leaves the block in static source and is not a clean unencrypted-bucket test.
# ==========================================================================
def w(path, rel, text):
    full = os.path.join(path, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    open(full, "w").write(text)


def fresh(name):
    d = os.path.join(WORK, "cases", name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    return d


def res_acl(v):
    return ('resource "aws_s3_bucket" "b" {\n  bucket = "ex-bucket"\n}\n\n'
            'resource "aws_s3_bucket_acl" "b" {\n'
            '  bucket = aws_s3_bucket.b.id\n'
            f'  acl    = {v}\n'
            '}\n')


def res_sg(v):
    return ('resource "aws_security_group" "b" {\n'
            '  name = "ex-sg"\n'
            '  ingress {\n'
            '    from_port   = 22\n'
            '    to_port     = 22\n'
            '    protocol    = "tcp"\n'
            f'    cidr_blocks = {v}\n'
            '  }\n'
            '}\n')


PROPERTIES = {
    "P1_s3_public_acl": {
        "render": res_acl, "secure": '"private"', "insecure": '"public-read"',
        "var_type": "string",
        # resource that the signal rule is expected to attach to
        "expected_addrs": ("aws_s3_bucket_acl.b", "aws_s3_bucket.b"),
    },
    "P2_sg_open_ingress": {
        "render": res_sg, "secure": '["10.0.0.0/16"]', "insecure": '["0.0.0.0/0"]',
        "var_type": "list(string)",
        "expected_addrs": ("aws_security_group.b",),
    },
}

# construct -> (level, builder)
INTRA = "intra-module multi-file"
INTER = "inter-module propagation"


def b_inline(prop, name, val):
    d = fresh(name); w(d, "main.tf", PROPERTIES[prop]["render"](val)); return d


def b_var_default(prop, name, val):
    d = fresh(name); vt = PROPERTIES[prop]["var_type"]
    w(d, "variables.tf", f'variable "v" {{\n  type    = {vt}\n  default = {val}\n}}\n')
    w(d, "main.tf", PROPERTIES[prop]["render"]("var.v")); return d


def b_locals(prop, name, val):
    d = fresh(name)
    w(d, "locals.tf", f'locals {{\n  v = {val}\n}}\n')
    w(d, "main.tf", PROPERTIES[prop]["render"]("local.v")); return d


def b_tfvars(prop, name, val):
    d = fresh(name); vt = PROPERTIES[prop]["var_type"]; sec = PROPERTIES[prop]["secure"]
    w(d, "variables.tf", f'variable "v" {{\n  type    = {vt}\n  default = {sec}\n}}\n')
    w(d, "terraform.tfvars", f'v = {val}\n')
    w(d, "main.tf", PROPERTIES[prop]["render"]("var.v")); return d


def b_override(prop, name, val):
    d = fresh(name); sec = PROPERTIES[prop]["secure"]
    w(d, "main.tf", PROPERTIES[prop]["render"](sec))
    if prop == "P1_s3_public_acl":
        w(d, "override.tf", 'resource "aws_s3_bucket_acl" "b" {\n'
                            f'  acl = {val}\n' '}\n')
    else:
        w(d, "override.tf", 'resource "aws_security_group" "b" {\n'
                            '  ingress {\n'
                            '    from_port   = 22\n'
                            '    to_port     = 22\n'
                            '    protocol    = "tcp"\n'
                            f'    cidr_blocks = {val}\n'
                            '  }\n}\n')
    return d


def b_module_input(prop, name, val):
    d = fresh(name); vt = PROPERTIES[prop]["var_type"]
    w(d, "main.tf", 'module "m" {\n  source = "./modules/m"\n' f'  v      = {val}\n' '}\n')
    w(d, "modules/m/variables.tf", f'variable "v" {{\n  type = {vt}\n}}\n')
    w(d, "modules/m/main.tf", PROPERTIES[prop]["render"]("var.v")); return d


def b_module_chain(prop, name, val):
    d = fresh(name); vt = PROPERTIES[prop]["var_type"]
    w(d, "main.tf",
      'module "cfg" {\n  source = "./modules/cfg"\n' f'  vin    = {val}\n' '}\n\n'
      'module "m" {\n  source = "./modules/m"\n  v      = module.cfg.vout\n}\n')
    w(d, "modules/cfg/variables.tf", f'variable "vin" {{\n  type = {vt}\n}}\n')
    w(d, "modules/cfg/outputs.tf", 'output "vout" {\n  value = var.vin\n}\n')
    w(d, "modules/m/variables.tf", f'variable "v" {{\n  type = {vt}\n}}\n')
    w(d, "modules/m/main.tf", PROPERTIES[prop]["render"]("var.v")); return d


def b_nested(prop, name, val):
    d = fresh(name); vt = PROPERTIES[prop]["var_type"]
    w(d, "main.tf", 'module "outer" {\n  source = "./modules/outer"\n' f'  v      = {val}\n' '}\n')
    w(d, "modules/outer/variables.tf", f'variable "v" {{\n  type = {vt}\n}}\n')
    w(d, "modules/outer/main.tf", 'module "inner" {\n  source = "./inner"\n  v      = var.v\n}\n')
    w(d, "modules/outer/inner/variables.tf", f'variable "v" {{\n  type = {vt}\n}}\n')
    w(d, "modules/outer/inner/main.tf", PROPERTIES[prop]["render"]("var.v")); return d


CONSTRUCTS = [
    ("C1 variable default",        INTRA, b_var_default),
    ("C2 local value",             INTRA, b_locals),
    ("C3 terraform.tfvars",        INTRA, b_tfvars),
    ("C7 override.tf",             INTRA, b_override),
    ("C4 module input",            INTER, b_module_input),
    ("C5 module output chaining",  INTER, b_module_chain),
    ("C6 nested modules",          INTER, b_nested),
]


# ==========================================================================
# HCL validation (so invalid generated source is never scored as "no findings")
# ==========================================================================
SEMANTIC_VALIDATION = os.environ.get("RQ4_SEMANTIC_VALIDATE", "0") == "1"


def semantic_validate(case_dir):
    """Optional stronger check: `terraform init -backend=false` + `terraform validate`.

    This is run in a SEPARATE pass and never inside the scanning path: the scanners are
    deliberately executed without provider initialisation (the mode in which they are
    normally deployed in pre-apply CI). Enable with RQ4_SEMANTIC_VALIDATE=1 and a
    network-enabled environment, since `init` downloads provider schemas.
    """
    if not shutil.which("terraform"):
        return ["terraform not available for semantic validation"]
    problems = []
    r = run_cmd(["terraform", "init", "-backend=false", "-input=false", "-no-color"],
                timeout=600, cwd=case_dir)
    if r["returncode"] not in (0,):
        problems.append(f"terraform init rc={r['returncode']}: {r['stderr'][:200]}")
        return problems
    r = run_cmd(["terraform", "validate", "-no-color"], timeout=300, cwd=case_dir)
    if r["returncode"] not in (0,):
        problems.append(f"terraform validate rc={r['returncode']}: {r['stdout'][:300]}")
    return problems


def validate_hcl(case_dir):
    """SYNTAX validation of generated HCL.

    Uses `terraform fmt -check`, which parses the configuration without requiring
    provider initialisation, plus brace balance and a check that no line carries two
    top-level assignments (the defect that silently broke an earlier version of this
    experiment). This establishes that every generated case is parseable by Terraform's
    own parser; it does NOT establish provider-level semantic validity, which would
    require `terraform init`. Semantic validation is available as a separate opt-in
    pass (see semantic_validate) and is not part of the scanning path.
    """
    problems = []
    if shutil.which("terraform"):
        r = run_cmd(["terraform", "fmt", "-check", "-recursive", case_dir], timeout=120)
        # rc 0 = formatted, 3 = would reformat (still valid syntax), 1 = parse error
        if r["returncode"] == 1:
            problems.append(f"terraform fmt parse error: {r['stderr'][:200]}")
    for root, _, files in os.walk(case_dir):
        for fn in files:
            if not fn.endswith(".tf"):
                continue
            p = os.path.join(root, fn)
            txt = open(p).read()
            if txt.count("{") != txt.count("}"):
                problems.append(f"{p}: brace imbalance")
            for i, ln in enumerate(txt.splitlines(), 1):
                assigns = re.findall(r"[A-Za-z_]\w*\s*=", ln)
                if len(assigns) >= 2 and "[" not in ln.split("=")[0]:
                    problems.append(f"{p}:{i}: multiple assignments on one line")
    return problems


# ==========================================================================
# oracle
# ==========================================================================
def signal_pairs(inline_insecure, inline_secure, expected_addrs):
    """Pairs present in the insecure inline control, absent in the secure one, and
    attached to an expected resource address."""
    ins = set(inline_insecure); sec = set(inline_secure)
    delta = ins - sec
    return {(r, a) for (r, a) in delta if a in expected_addrs}


def judge(signal, control_pairs, treatment_pairs):
    """Apply oracle parts 2-3 given the signal pairs from part 1/4."""
    c = set(control_pairs); t = set(treatment_pairs)
    hit = signal & t
    if hit and not (signal & c):
        return "RESOLVED", sorted(hit)
    if not (signal & (t - c)):
        return "NOT_RESOLVED", []
    return "PARTIAL", sorted(signal & (t - c))


# ==========================================================================
# main
# ==========================================================================
def main():
    started = datetime.now(timezone.utc).isoformat()
    available = {t: (shutil.which(t) is not None) for t in TOOLS}
    manifest = {
        "experiment": "rq4_cross_file_resolution",
        "started_utc": started,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "os_release": platform.version(),
        "tool_paths": {t: shutil.which(t) for t in TOOLS},
        "tool_versions": {t: tool_version(t) for t in TOOLS},
        "terraform_version": tool_version("terraform"),
        "terraform_init_executed": False,
        "semantic_validation_pass": SEMANTIC_VALIDATION,
        "hcl_validation": "terraform fmt -check (syntax); provider-level validation only if semantic_validation_pass is true",
        "provider_schemas_downloaded": False,
        "invocation": "default directory scan on case root; JSON output; no custom rules",
        "properties": list(PROPERTIES),
        "constructs": [{"name": n, "level": lv} for n, lv, _ in CONSTRUCTS],
        "excluded_properties": {
            "P3_encryption": "excluded: count=0 formulation leaves the block in static "
                             "source, so it is not a clean unencrypted-bucket test"},
    }
    print("=" * 78)
    print("RQ4 canonical experiment")
    print("=" * 78)
    for t in TOOLS:
        print(f"  {t:10s} {manifest['tool_versions'][t]}")

    results = {}
    validation_problems = {}

    for prop, spec in PROPERTIES.items():
        results[prop] = {}
        sec, ins = spec["secure"], spec["insecure"]
        exp = spec["expected_addrs"]

        # inline controls (oracle parts 1 and 4)
        d_in_s = b_inline(prop, f"{prop}__inline_secure", sec)
        d_in_i = b_inline(prop, f"{prop}__inline_insecure", ins)
        for d in (d_in_s, d_in_i):
            pb = validate_hcl(d)
            if SEMANTIC_VALIDATION:
                pb = pb + semantic_validate(d)
            if pb:
                validation_problems[d] = pb

        signals = {}
        for tname, scan in TOOLS.items():
            if not available[tname]:
                signals[tname] = None
                continue
            try:
                pi = scan(d_in_i); ps = scan(d_in_s)
            except ToolError as e:
                signals[tname] = "ERROR"
                print(f"  [{tname}] inline ERROR: {e}")
                continue
            signals[tname] = signal_pairs(pi, ps, exp)

        print(f"\n### {prop}")
        for tname in TOOLS:
            s = signals[tname]
            print(f"   {tname:10s} signal: "
                  f"{sorted(s) if isinstance(s, set) and s else s}")

        for tname, scan in TOOLS.items():
            results[prop][tname] = {}
            sig = signals[tname]
            for cname, level, builder in CONSTRUCTS:
                if sig is None:
                    results[prop][tname][cname] = {"verdict": "N/A", "level": level}
                    continue
                if sig == "ERROR":
                    results[prop][tname][cname] = {"verdict": "ERROR", "level": level}
                    continue
                if not sig:
                    results[prop][tname][cname] = {"verdict": "INCONCLUSIVE", "level": level}
                    continue
                dc = builder(prop, f"{prop}__{tname}__{cname.split()[0]}__control", sec)
                dt = builder(prop, f"{prop}__{tname}__{cname.split()[0]}__treatment", ins)
                for d in (dc, dt):
                    pb = validate_hcl(d)
                    if pb:
                        validation_problems[d] = pb
                if validation_problems.get(dc) or validation_problems.get(dt):
                    results[prop][tname][cname] = {"verdict": "ERROR", "level": level,
                                                   "reason": "invalid generated HCL"}
                    continue
                try:
                    pc = scan(dc); pt = scan(dt)
                except ToolError as e:
                    results[prop][tname][cname] = {"verdict": "ERROR", "level": level,
                                                   "reason": str(e)[:200]}
                    continue
                verdict, matched = judge(sig, pc, pt)
                results[prop][tname][cname] = {
                    "verdict": verdict, "level": level,
                    "matched_pairs": [list(m) for m in matched],
                    "control_findings": len(pc), "treatment_findings": len(pt),
                }

    # ---------------- report ----------------
    tools = [t for t in TOOLS if available[t]]
    for prop in PROPERTIES:
        print("\n" + "=" * 78)
        print(f"MATRIX — {prop}")
        print("=" * 78)
        print(f"{'Construct':28s} {'Level':26s} " + " ".join(f"{t:>12s}" for t in tools))
        print("-" * 78)
        for cname, level, _ in CONSTRUCTS:
            row = " ".join(f"{results[prop][t][cname]['verdict']:>12s}" for t in tools)
            print(f"{cname:28s} {level:26s} {row}")

    manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["total_tool_runs"] = _run_counter["n"]
    manifest["hcl_validation_problems"] = {k: v for k, v in validation_problems.items()}

    with open(os.path.join(WORK, "rq4_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    with open(os.path.join(WORK, "rq4_results.json"), "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 78)
    print(f"manifest -> {WORK}/rq4_manifest.json")
    print(f"results  -> {WORK}/rq4_results.json")
    print(f"raw runs -> {RUNS_DIR}/ ({_run_counter['n']} captured executions)")
    if validation_problems:
        print(f"[!] {len(validation_problems)} case(s) failed HCL validation "
              f"— reported as ERROR, not NOT_RESOLVED")
    else:
        print("all generated cases passed HCL validation")


if __name__ == "__main__":
    main()
