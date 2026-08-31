# Prevalence of Cross-File Dependencies in Terraform and Their Resolution by Security Scanners

Replication package for an empirical study of cross-file and cross-module dependencies in
Terraform, and of how much of that structure security scanners actually resolve.

The study has two halves. The first characterises cross-file dependencies across **62,406**
open-source Terraform repositories from the public [TerraDS](https://zenodo.org/records/14217386)
dataset. The second tests, under controls, whether four widely used security scanners can
follow configuration values across the file and module boundaries that structure creates.

> The manuscript itself is not included in this repository. This is the replication
> package: code, derived data, and the raw evidence behind the reported results.

---

## Research questions

| | |
|---|---|
| **RQ1** | How common are cross-file and cross-module dependencies, and how are they distributed? |
| **RQ2** | What recurring patterns characterise them, and which cross file boundaries? |
| **RQ3** | How often do they target modules declaring security-sensitive resources? |
| **RQ4** | Which cross-file constructs do security scanners actually resolve, and where does resolution break down? |

## Headline findings

**Characterisation (RQ1–RQ3)**

| Finding | Value |
|---|---|
| Repositories with at least one cross-file dependency | 21,665 (**34.7%**) |
| Most frequent dependency pattern | `local_traversal` (**38.5%**) |
| Cross-file share of all module dependencies | **61.2%** (161,749 of 264,352) |
| Repositories where such a dependency targets a security-sensitive module | **9,035** |
| Strongest correlate of coupling | module count (Spearman rho = **0.752**), not popularity (stars rho = 0.113) |

**Capability (RQ4)** — support is *graded*, not binary:

| Construct | Level | Checkov | tfsec | Terrascan | Trivy |
|---|---|---|---|---|---|
| C1 variable default (separate file) | intra-module | ✓ | ✓ | ✓ | ✓ |
| C2 local value (separate file) | intra-module | ✓ | ✓ | ✓ | ✓ |
| C3 `terraform.tfvars` | intra-module | ✓ | — | — | — |
| C7 `override.tf` | intra-module | property-dependent | property-dependent | — | property-dependent |
| C4 module input | inter-module | ✓ | — | ✓ | — |
| C5 module output chaining | inter-module | ✓ | — | — | — |
| C6 nested modules (two levels) | inter-module | ✓ | — | — | — |

Every scanner resolves the shortest intra-module flows. Only Checkov resolves
`terraform.tfvars`. Complete inter-module propagation appears only in Checkov, with
Terrascan handling the direct module-input case. Override-file handling depends on the
security property tested.

---

## Layout

```
├── src/                     analysis and experiment code
│   ├── core.py                  canonical classifier, resolver, security-resource set
│   ├── phase3_analysis.py       RQ1–RQ3 corpus analysis
│   ├── phase4_analysis.py       figures and tables
│   ├── phase5_stats.py          correlations, distribution fits, regression, resolver audit
│   ├── phase7_dataset_distributions.py   corpus distributions, unresolved-edge breakdown
│   ├── phase8_resolver_validation.py     resolver resolver consistency and recovery checks
│   ├── rq4_experiment.py        THE RQ4 experiment (four-part oracle)
│   ├── make_rq4_tables.py       generates the result tables from the raw results
│   ├── verify_results.py        integrity check over results, tables and run records
│   └── deprecated/              superseded iterations, with a note on why
├── notebooks/               Colab-ready; see notebooks/README.md
├── data/                    where TerraDS goes (not redistributed; see data/README.md)
├── results/                 the RQ4 evidence: manifest, verdicts, 249 raw run records
│   └── derived/                 per-repository dataset and audit sample we produced
├── figures/                 publication figures
├── Dockerfile               pinned scanner versions for the RQ4 experiment
└── requirements.txt         Python dependencies for the corpus analysis
```

## Reproducing

### RQ4 (self-contained, no dataset needed)

```bash
docker build -t crossfile-rq4 .
docker run --rm -v "$PWD/rq4_out:/out" crossfile-rq4
```

Or on Colab, run `notebooks/RQ4_Canonical_Experiment.ipynb`. Either path writes
`rq4_manifest.json`, `rq4_results.json` and one record per tool execution under
`raw_runs/`.

### RQ1–RQ3 (needs TerraDS)

```bash
pip install -r requirements.txt
# place TerraDS.sqlite at data/terrads/TerraDS.sqlite  (see data/README.md)
python src/phase3_analysis.py     # prevalence, patterns, security surface
python src/phase5_stats.py        # statistics; writes results/derived/per_repo.csv
python src/phase4_analysis.py     # figures and tables
```

Or run the `TerraDS_*` notebooks in order.

### Checking the package is internally consistent

```bash
python src/verify_results.py
```

Regenerates the result tables from `results/rq4_results.json`, compares them with the
committed copy, checks that every verdict uses the declared vocabulary, and confirms the
raw execution records match the count in the manifest. Current status: **PASS**.

---

## Provenance

The reported RQ4 results come from a single run with these versions, recorded in
`results/rq4_manifest.json` and pinned in the `Dockerfile`:

Checkov 3.3.13 · tfsec v1.28.14 · Terrascan v1.19.9 · Trivy 0.74.0 · Terraform 1.10.5
(Terraform is used for syntax validation only; `terraform init` is never run in the
scanning path.)

249 tool executions were captured, none timed out, and every generated test case passed
HCL syntax validation.

## Method in brief

Each repository is reduced to a **module-level dependency graph** built from declared
module calls. Every dependency is classified by a deterministic source-based taxonomy,
and cross-file dependency targets are linked to a catalogue of security-sensitive resource
types. For RQ4, each construct is generated in three matched variants — control, treatment,
and an inline positive control — and a four-part oracle decides the verdict: the fired rule
must match the tool's own signal rule, attach to the expected resource address, differ from
the control, and be confirmed by the inline control. Verdicts of RESOLVED, NOT RESOLVED,
INCONCLUSIVE, ERROR and N/A are kept distinct, so an execution failure can never be
recorded as a blind spot.

## Why the exploratory scripts were superseded

Two measurement defects were found and fixed while developing the experiment. They are
documented because each changed a reported verdict, and because either would be easy to
repeat in a similar study:

1. Filtering findings by an `acl` substring missed Checkov's public-read rule
   (`CKV_AWS_20`) and produced a spurious blind-spot signal.
2. Comparing only sets of rule identifiers, without matching the resource address a
   finding attaches to, scores a construct NOT RESOLVED whenever the same rule also fires
   on an unrelated resource in the control run.

The canonical experiment fixes both: it matches on `(rule, resource address)` and keeps
ERROR and INCONCLUSIVE distinct from NOT RESOLVED. The superseded scripts are kept under
`src/deprecated/` and `notebooks/deprecated/` with an explanation.

## Data

**TerraDS** is not redistributed here; download it from Zenodo (see `data/README.md`).
The datasets this study *produced* are version-controlled under `results/derived/`.

## Citation

If you use this package, please cite the accompanying article once it is published, and
this repository via its Zenodo DOI (see below).

```bibtex
@software{crossfile_terraform_package,
  author = {Draz, Moatasem M.},
  title  = {Cross-file dependencies in Terraform: replication package},
  year   = {2026},
  doi    = {10.5281/zenodo.XXXXXXX}
}
```

## License

Code released under the MIT License (see `LICENSE`). TerraDS is subject to its own license.
