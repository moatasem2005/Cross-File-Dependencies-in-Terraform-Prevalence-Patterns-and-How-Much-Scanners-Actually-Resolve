# data/

## What belongs here

The **TerraDS** dataset — a single SQLite file of roughly 300 MB.

It is **not** redistributed in this repository, for two reasons: it is already publicly
archived and citable at its own DOI, and re-hosting a large third-party dataset would
duplicate it without adding provenance. Download it once and place it here:

```
data/terrads/TerraDS.sqlite
```

Source: https://zenodo.org/records/14217386

`notebooks/TerraDS_Explorer.ipynb` fetches it automatically on Colab, so on that path you
do not need to place anything here by hand.

## Why this directory looks empty

Everything under `data/` except this file is git-ignored. That keeps the repository small
and avoids shipping a copy of someone else's dataset.

## Where the data we produced lives

The derived datasets — the ones this study generated rather than downloaded — are **not**
here. They are version-controlled under `results/derived/`, because they are outputs of
the analysis and are needed to reproduce the figures and statistics:

| File | What it is |
|---|---|
| `results/derived/per_repo.csv` | One row per repository (62,406 rows): module count, edge counts, cross-file flags, security-reach flag, stars, forks, size |
| `results/derived/resolver_audit.csv` | The 200-edge resolver audit sample |
| `results/derived/rq1_rq3_summary.json` | Aggregate counts behind the RQ1–RQ3 figures and tables |

The RQ4 experiment artefacts (manifest, per-construct verdicts, and 249 captured tool
executions) are in `results/` alongside them.
