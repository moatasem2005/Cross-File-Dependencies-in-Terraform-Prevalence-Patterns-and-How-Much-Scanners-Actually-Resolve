# Pushing this to GitHub

The repository is already initialised with a single clean commit on `main`, so you only
need to create the remote and push.

## 1. Create an empty repository on GitHub

Go to github.com → **New repository**. Suggested name:

```
terraform-crossfile-study
```

Leave it **empty** — no README, no .gitignore, no licence. Those already exist here and
GitHub would otherwise create a conflicting first commit.

## 2. Push

From inside this folder:

```bash
git remote add origin https://github.com/<YOUR-USERNAME>/terraform-crossfile-study.git
git push -u origin main
```

If your account uses SSH:

```bash
git remote add origin git@github.com:<YOUR-USERNAME>/terraform-crossfile-study.git
git push -u origin main
```

## 3. Confirm it verifies itself

A GitHub Actions workflow runs on every push. It checks that

- the result tables regenerate exactly from the raw results,
- every verdict uses the declared vocabulary,
- the raw execution records match the manifest count,
- every script parses and every notebook is valid JSON.

After the first push, open the **Actions** tab. A green check means anyone who clones the
repository gets the same verification you did.

## 4. Mint a DOI

1. Sign in to zenodo.org with GitHub and enable the switch for this repository.
2. On GitHub: **Releases → Create a new release**, tag `v1.0.0`, publish.
3. Zenodo archives the release and issues a DOI.
4. Put that DOI in `README.md` (replacing `10.5281/zenodo.XXXXXXX`) and in the
   manuscript's Data availability section.

## What is deliberately not here

- **The manuscript and cover letter.** Kept separate until the article is published.
- **TerraDS itself.** It is a large third-party dataset with its own DOI; `data/README.md`
  explains where to get it. The datasets *this study produced* are under
  `results/derived/` and are version-controlled.
