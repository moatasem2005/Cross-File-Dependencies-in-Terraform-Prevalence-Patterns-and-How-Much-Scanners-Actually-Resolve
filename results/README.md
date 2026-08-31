# Results artefacts — the evidence behind the reported RQ4 tables

These are the actual outputs of the run reported in the manuscript, not a transcription.

| File | What it is |
|---|---|
| `rq4_manifest.json` | tool versions, platform, invocation, timestamps, run count |
| `rq4_results.json` | verdict per property × tool × construct, with matched rule/address pairs |
| `raw_runs/` | 249 records: command, exit code, stdout, stderr, duration for every execution |
| `rq4_tables_check.txt` | tables generated from `rq4_results.json` by `src/make_rq4_tables.py` |
| `rq4_tables.md`, `rq4_tables.json` | the same tables in readable / machine-readable form |

## Verify the package is internally consistent

```bash
python src/verify_results.py
```

Regenerates the tables from `rq4_results.json`, compares them with the committed copy,
validates the verdict vocabulary, and checks the raw execution records against the
manifest. Current status: **PASS**.

To regenerate the tables rather than check them:

```bash
python src/make_rq4_tables.py results/rq4_results.json results/
```


## Provenance of this run

| | |
|---|---|
| Checkov | 3.3.13 |
| tfsec | v1.28.14 |
| Terrascan | v1.19.9 |
| Trivy | 0.74.0 |
| Terraform | v1.10.5 (syntax validation only) |
| Python | 3.13.15 |
| Platform | Linux 6.6.122 x86_64, glibc 2.35 |
| Executions captured | 249 (0 timeouts) |
| `terraform init` run | no |
| Provider schemas fetched | no |
| HCL validation problems | 0 |

These versions are pinned in the repository `Dockerfile`.

## Scope

The encryption property is excluded from the results, as recorded in the manifest: a
`count = 0` formulation leaves the encryption block present in the static source, so it
is not a clean unencrypted-bucket test.
