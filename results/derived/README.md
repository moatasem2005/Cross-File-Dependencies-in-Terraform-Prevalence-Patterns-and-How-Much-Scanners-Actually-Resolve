# Derived datasets

These are outputs of the analysis in this repository, not third-party data. They are
version-controlled so that the figures, tables, and statistics in the manuscript can be
regenerated without first re-running the full corpus analysis over TerraDS.

| File | Rows | Produced by | Used for |
|---|---|---|---|
| `per_repo.csv` | 62,406 | `src/phase5_stats.py` | RQ1 distribution figure, correlations, logistic regression |
| `resolver_audit.csv` | 200 | `src/phase5_stats.py` | Resolver consistency check |
| `rq1_rq3_summary.json` | — | `src/phase3_analysis.py` | Aggregate counts for the RQ1–RQ3 figures and tables |

## `per_repo.csv` columns

| Column | Meaning |
|---|---|
| `repo_id` | TerraDS repository identifier |
| `n_modules` | Modules declared in the repository |
| `total_edges` | Module dependencies declared |
| `cf_edges` | Of those, dependencies that cross a file boundary |
| `has_cf` | 1 if the repository has any cross-file dependency |
| `sec_reached` | 1 if a cross-file dependency targets a module declaring a security-sensitive resource |
| `stars`, `forks`, `size_kb` | Repository metadata from TerraDS |

## `resolver_audit.csv` columns

`src_dir`, `source`, `target`, `resolved` — the calling module directory, the raw module
source string, the normalised target path, and whether it matched a module in the same
repository.

## Regenerating these

```bash
# with data/terrads/TerraDS.sqlite in place
python src/phase3_analysis.py     # aggregate counts
python src/phase5_stats.py        # per_repo.csv + resolver_audit.csv + statistics
```
