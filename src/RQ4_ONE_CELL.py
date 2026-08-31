# ============================================================================
# RQ4 — run the canonical experiment and download the artefacts.  ONE CELL.
# Produces: rq4_manifest.json, rq4_results.json, raw_runs/, rq4_tables_check.txt
# packaged as rq4_artifacts.zip and downloaded automatically.
# Do NOT restart the runtime before the download finishes.
# ============================================================================
import base64, zlib, os, sys, shutil, subprocess, glob, json

SRC = {
"core.py": "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",
"rq4_experiment.py": "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",
"make_rq4_tables.py": "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"
}

os.makedirs("/content/src", exist_ok=True)
for name, b in SRC.items():
    open(f"/content/src/{name}", "w").write(zlib.decompress(base64.b64decode(b)).decode())
sys.path.insert(0, "/content/src")
print("sources written to /content/src")

def sh(c, t=1800):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)

def show(step, r):
    if r.returncode != 0:
        print(f"   [!] {step}: rc={r.returncode}")
        for ln in ((r.stderr or r.stdout or "").strip().splitlines() or [])[-4:]:
            print("       ", ln[:160])

# ------------------------------------------------ install the four scanners
print("\n>> installing scanners (2-4 min)")
show("checkov", sh("pip install -q --upgrade checkov"))
if not shutil.which("checkov"):
    for c in ["/usr/local/bin", os.path.expanduser("~/.local/bin"), os.path.join(sys.prefix, "bin")]:
        if os.path.exists(os.path.join(c, "checkov")):
            os.environ["PATH"] = c + os.pathsep + os.environ["PATH"]; break
if not shutil.which("checkov"):
    if sh(f'"{sys.executable}" -m checkov.main --version').returncode in (0, 1):
        open("/usr/local/bin/checkov", "w").write(
            f'#!/bin/sh\nexec "{sys.executable}" -m checkov.main "$@"\n')
        os.chmod("/usr/local/bin/checkov", 0o755)

tag = sh("curl -sSL https://api.github.com/repos/aquasecurity/tfsec/releases/latest "
         "| grep -m1 '\"tag_name\"' | cut -d'\"' -f4").stdout.strip() or "v1.28.14"
show("tfsec", sh(f"curl -fsSL https://github.com/aquasecurity/tfsec/releases/download/{tag}/tfsec-linux-amd64 "
                 f"-o /usr/local/bin/tfsec && chmod +x /usr/local/bin/tfsec"))

if not shutil.which("terrascan"):
    v = sh("curl -sSL https://api.github.com/repos/tenable/terrascan/releases/latest "
           "| grep -m1 '\"tag_name\"' | cut -d'\"' -f4 | sed 's/^v//'").stdout.strip() or "1.19.9"
    show("terrascan", sh(f"curl -fsSL https://github.com/tenable/terrascan/releases/download/v{v}/"
                         f"terrascan_{v}_Linux_x86_64.tar.gz -o /tmp/ts.tgz && cd /tmp && "
                         f"tar -xzf ts.tgz terrascan && mv terrascan /usr/local/bin/ && chmod +x /usr/local/bin/terrascan"))

show("trivy", sh("curl -sSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh "
                 "| sh -s -- -b /usr/local/bin"))
show("terraform", sh("curl -fsSL https://releases.hashicorp.com/terraform/1.10.5/terraform_1.10.5_linux_amd64.zip "
                     "-o /tmp/tf.zip && unzip -oq /tmp/tf.zip -d /usr/local/bin"))

print("\n=== VERIFICATION ===")
missing = []
for t, c in [("checkov","checkov --version"), ("tfsec","tfsec --version"),
             ("terrascan","terrascan version"), ("trivy","trivy --version"),
             ("terraform","terraform version")]:
    if not shutil.which(t):
        missing.append(t); print(f"  {t:11s} MISSING"); continue
    r = sh(c, 120)
    print(f"  {t:11s} {((r.stdout or r.stderr).strip().splitlines() or ['?'])[0][:70]}")
scanners_missing = [t for t in ["checkov","tfsec","terrascan","trivy"] if t in missing]
if scanners_missing:
    print("\n[!] missing scanner(s):", ", ".join(scanners_missing))
    print("    Those will be recorded as N/A. Re-run this cell for a complete matrix.")

# ------------------------------------------------ run the experiment
print("\n>> running the experiment")
import rq4_experiment
rq4_experiment.main()

# ------------------------------------------------ generate tables from results
WORK = rq4_experiment.WORK
res = os.path.join(WORK, "rq4_results.json")
if os.path.exists(res):
    print("\n>> generating manuscript tables from rq4_results.json")
    sh(f'"{sys.executable}" /content/src/make_rq4_tables.py "{res}" "{WORK}"')
    chk = os.path.join(WORK, "rq4_tables_check.txt")
    if os.path.exists(chk):
        print(open(chk).read())

    # ------------------------------------------------ package + download
    zp = shutil.make_archive("/content/rq4_artifacts", "zip", WORK)
    print(f"\npackaged: {zp} ({os.path.getsize(zp)/1e6:.1f} MB)")
    print("contains:",
          len(glob.glob(os.path.join(WORK, "raw_runs", "*.json"))), "raw run records")
    try:
        from google.colab import files
        files.download(zp)
        print("download started")
    except Exception as e:
        print("auto-download unavailable:", e)
        print("Open the Files pane (folder icon on the left) and download rq4_artifacts.zip")
else:
    print("[!] rq4_results.json was not produced — the experiment did not complete")
