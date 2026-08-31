# Notebooks

## The declared run path

**`RQ4_Canonical_Experiment.ipynb`** is the only notebook that produces the RQ4 results
reported in the manuscript. `RQ4_ONE_CELL.ipynb` is the same experiment packaged as a
single copy-paste cell.

| Notebook | Purpose |
|---|---|
| `RQ4_Canonical_Experiment.ipynb` | **The RQ4 experiment.** Four-part oracle, address matching, distinct ERROR/INCONCLUSIVE verdicts, manifest, HCL validation. |
| `RQ4_ONE_CELL.ipynb` | Same experiment, one cell, installs tools and downloads the artefacts. |
| `Download_RQ4_Artifacts.ipynb` | Retrieves `rq4_manifest.json`, `rq4_results.json` and `raw_runs/` from a completed run. |
| `TerraDS_Explorer.ipynb` | Downloads and inspects the TerraDS dataset. |
| `TerraDS_DeepProbe.ipynb` | Schema probe over the dataset. |
| `TerraDS_Phase3_Analysis.ipynb` | RQ1–RQ3 corpus analysis. |
| `TerraDS_Phase4_Figures.ipynb` | Figures and tables for RQ1–RQ3. |
| `Phase5_Statistics.ipynb` | Correlations, distribution fits, regression, resolver audit. |

## `deprecated/`

Exploratory iterations, retained only to document how the design evolved. **They do not
back any number in the manuscript**, and each carries a warning cell at the top.

Two defects in particular are why they were superseded:

1. Their `P3` encryption probe is invalid — a cross-file `count = 0` leaves the
   encryption block in the static source, so it is not a clean unencrypted-bucket test.
   That property is excluded from the reported results.
2. Earlier versions compared only rule-identifier sets, without matching the expected
   resource address, producing verdicts later shown to be wrong.
