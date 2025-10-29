Publishing ScamiFy (essentials only)

This file explains how to push only the essential project files to GitHub from Windows PowerShell.

What to include (recommended essentials)
- Backend: `backend/app.py`, `backend/requirements-min.txt`, any small helper modules (`backend/*.py`), `backend/README.md` (if present).
- Extension: `scamify-extension/manifest.json`, `scamify-extension/background.js`, `scamify-extension/content.js`, `scamify-extension/popup.html`, `scamify-extension/popup.js`, `scamify-extension/styles.css`, `scamify-extension/icons/*`.
- Docs: `README.md`, `PUBLISH.md`.

What NOT to include in the repo (put in Releases or external storage)
- Large model files: `*.h5`, `*.pt`, `*.pkl` (e.g. `ann/optimized_ann_90_9acc.h5`, `ann/*.h5`, `LSTM/*.h5`) — use GitHub Releases or Git LFS.
- Local database: `backend/database.db`.
- Virtual environments: `.venv/`.

Prepare the repo locally (PowerShell)

1. Initialize git and create a branch
```powershell
cd "d:\trial\Extension"
# Initialize a repo in the Extension folder
git init
# Use main branch
git checkout -b main
```

2. Stage only the essential files (example)
```powershell
# Backend essentials
git add backend\app.py backend\requirements-min.txt

# Extension essentials
git add scamify-extension\manifest.json scamify-extension\background.js scamify-extension\content.js scamify-extension\popup.html scamify-extension\popup.js scamify-extension\styles.css

# Icons (if small)
git add scamify-extension\icons\*

# Docs
git add README.md PUBLISH.md
```

3. Commit
```powershell
git commit -m "Initial minimal ScamiFy: backend and extension (essentials)"
```

4a. Create GitHub repo using the web UI
- Open https://github.com/new
- Pick a name (e.g. `Scamify`) and create repo
- Copy the `git remote add` command GitHub shows and run it, for example:
```powershell
git remote add origin https://github.com/<your-username>/Scamify.git
git push -u origin main
```

4b. (Optional) Create repo using GitHub CLI (`gh`)
```powershell
# install gh if not present
gh auth login
gh repo create <your-username>/Scamify --public --source=. --remote=origin --push
```

Uploading model files / large artifacts
- Do NOT commit model binaries. Instead use GitHub Releases and upload model files there, or use Git LFS (requires setup and may cost).
- To create a release manually: in GitHub web go to "Releases" -> "Draft a new release" -> Upload model files and note down the URLs.

Example: create a release and attach `basic_lstm_model_best.h5`.

Post-publish steps
- Update your `README.md` to document how to download models and where to place them (e.g., `ann/` or `LSTM/`).
- If you used Releases, add links to the release assets in README.

If you want, I can:
- Create a minimal `backend/requirements-min.txt` (done).
- Create a short `README.md` or `backend/README.md` showing how to install and run the backend (I can create that next).
- Generate an example `.gitattributes` or Git LFS guidance.

Choose what to do next and I'll proceed (create README, run a dry commit, or prepare release instructions).