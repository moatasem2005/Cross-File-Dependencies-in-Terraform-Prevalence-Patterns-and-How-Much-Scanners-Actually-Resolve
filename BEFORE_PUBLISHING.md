# Before publishing this repository

The manuscript and cover letter are **not** in this repository; they are kept separately
until the article is published. What follows applies to the replication package itself.

## 1. Archive and mint a DOI

1. Push this repository to GitHub.
2. Enable the Zenodo–GitHub integration and cut a release. Zenodo mints a DOI.
3. Replace `10.5281/zenodo.XXXXXXX` in `README.md` with the real DOI.
4. Put the same DOI in the manuscript's Data availability section.

## 2. Check the package before the release

```bash
python src/verify_results.py
```

Must print **PASS**. It regenerates the result tables from the raw results, compares them
with the committed copy, validates the verdict vocabulary, and confirms the execution
records match the manifest.

## 3. If you edit the results

Never hand-edit anything under `results/`. Re-run the experiment instead:

```bash
docker build -t crossfile-rq4 .
docker run --rm -v "$PWD/rq4_out:/out" crossfile-rq4
python src/make_rq4_tables.py rq4_out/rq4_results.json rq4_out/
```

Then copy the new artefacts into `results/` and re-run the check above. The manuscript's
tables must be updated from the same output, so that the article and the package cannot
drift apart.

## 4. Licence

`LICENSE` is MIT in the author's name. TerraDS keeps its own licence and is not
redistributed here.
