# Scamify

A Chrome extension (Manifest V3) that flags likely phishing URLs as you browse, backed by a local Flask API and two ML models — a 53-feature ANN over URL structure, and an LSTM over page behaviour.

Hover a link, and a tooltip shows the classification (SAFE / SUSPICIOUS / PHISHING) with a confidence score.

> **Status: research project.** The trained model weights are not committed to this repo (see [Model artifacts](#model-artifacts)), so a fresh clone will not classify URLs until you supply them.

## Repository layout

```
Extension/
  phishing-extension/       # Chrome extension (Manifest V3)
  backend/                  # Flask API — app.py, requirements.txt, tests
  ANN-model/                # 53-feature extractor + prediction wrapper
  phish-stats-globe-main/   # Standalone Vite/React stats dashboard (not wired into the extension)
```

Docs: [ULTRA_ENHANCED_MODEL_REPORT.md](Extension/ULTRA_ENHANCED_MODEL_REPORT.md) (ANN feature set and thresholds), [BASIC_LSTM_MODEL_REPORT.md](Extension/BASIC_LSTM_MODEL_REPORT.md) (LSTM evaluation), [FEATURES_DOCUMENTATION.md](Extension/ANN-model/FEATURES_DOCUMENTATION.md).

## Setup

Requires Python 3.8+ and Chrome/Chromium.

### Backend

```bash
git clone https://github.com/bhargav-1910/Scamify-Extension.git
cd Scamify-Extension/Extension/backend

python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS/Linux

pip install -r requirements.txt
python app.py                  # serves on http://127.0.0.1:5000
```

`requirements.txt` pins TensorFlow, Selenium and Playwright for the full pipeline. For URL-only inference, `requirements-min.txt` is the smaller set.

### Extension

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. **Load unpacked** → select `Extension/phishing-extension`
4. Hover any link to see the tooltip

The extension expects the backend at `http://127.0.0.1:5000`.

## Model artifacts

The `.h5` model files and `.pkl` scalers are **not tracked in this repository**. The backend and the ANN wrapper look for:

| Path | Used by |
|---|---|
| `ann_model_ultra_enhanced.h5` + `scaler_ultra_enhanced.pkl` | `Extension/ANN-model/` wrapper |
| `basic_lstm_model_best.h5` + `feature_scaler.pkl` | LSTM behavioural pipeline |
| `models/ann_model.pkl` | `Extension/backend/app.py` |

Until these are present, endpoints return errors. Feature order matters — the scaler must be the one fitted during training, in the exact order given by `get_ultra_feature_names()` (53 entries).

## Models

Two separate models, evaluated to very different depths. Numbers below are the ones actually measured; where no evaluation exists, that is stated rather than estimated.

### LSTM — page behaviour (24 features)

Binary classifier over 24 behavioural features scraped per page via Selenium (SSL validity, redirects, forms, password fields, iframes, script counts, load time). Architecture: LSTM(128) → LSTM(64) → Dense(50/25/1), 132,295 parameters.

**Evaluation** — held-out 20% split of `merged_training_dataset.csv`, n = 200 test samples (99 legitimate / 101 phishing, near-balanced):

| Operating point | Accuracy | Precision | Recall | F1 | ROC AUC |
|---|---|---|---|---|---|
| Threshold 0.5 | 0.770 | 0.867 | 0.644 | 0.739 | 0.872 |
| Threshold 0.43 (F1-tuned) | 0.810 | 0.818 | 0.802 | 0.810 | 0.872 |
| After 10-epoch class-weighted retrain, thr 0.5 | 0.865 | 0.814 | 0.951 | 0.877 | 0.956 |

Recall is the weak metric here: at the default 0.5 threshold the model misses ~36% of phishing pages. Lowering the threshold to 0.43 trades precision for recall and is the better operating point; the short retrain improves recall further but has not been validated on an independent holdout.

Because the test split is close to 50/50, accuracy is not inflated by class imbalance in this case — but it is a small test set (n=200), so treat all figures as indicative rather than settled.

### ANN — URL structure (53 features)

Extracts 53 features from the URL string alone: structural counts, Shannon entropy of URL/domain/path, Levenshtein distance to a 355-domain known-legitimate list (typosquat detection), Cyrillic/mixed-script homograph flags, leet-speak substitutions, suspicious TLDs, and optional WHOIS domain age / SSL checks (network-backed, off by default).

Deterministic guardrails override the model toward *legitimate* for whitelisted domains and trusted subdomains, which suppresses false positives on major sites.

**Evaluation: none on a held-out dataset.** The only check in the repo is `Extension/ANN-model/test_ultra_enhanced_model.py`, a hand-written smoke test of 45 URLs (20 legitimate, 25 synthetic phishing). That is a sanity check, not a measurement — it has no train/test split, and the phishing URLs were authored to exercise specific features, so any score it produces is not a generalisation estimate.

Producing real numbers for this model means training and evaluating on a labelled corpus (e.g. PhishTank / OpenPhish against Tranco) and reporting precision and recall per class. Until then, treat the ANN as unquantified.

## API

Backend runs on `http://127.0.0.1:5000`.

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/check` | Lightweight inference used by the extension |
| `POST` | `/predict_url` | URL analysis with full feature output |
| `POST` | `/flag_url` | Flag a URL for review |
| `POST` | `/register`, `/login` | JWT auth |
| `GET` | `/get_global_stats`, `/get_user_stats` | Statistics |
| `GET` | `/get_extension_settings` · `POST` `/update_extension_settings` | Settings |
| `GET` | `/health` | Status and loaded-model info |

```bash
curl -X POST http://127.0.0.1:5000/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Features

- **Hover detection** — debounced URL analysis on link hover, with local caching to cut backend calls
- **Typosquat / homograph detection** — `paypa1.com`, `g00gle.com`, Cyrillic `аpple.com`
- **Download protection** — flags dangerous file types
- **Context menu** — right-click to analyse a URL
- **Stats dashboard** — scan history and global counters
- **JWT auth** — bcrypt password hashing, SQLite storage

## Testing

```bash
cd Extension/backend
python test_backend.py        # backend suite
python test_api.py            # endpoint checks

cd ..
python test_integration.py    # end-to-end
python test_url_analysis.py   # URL analysis
```

The ANN and LSTM tests require the model artifacts described above.

## Known limitations

- Model weights are not in the repo; a clone cannot classify without them
- The ANN has no held-out evaluation — see [Models](#ann--url-structure-53-features)
- LSTM recall at the default threshold is 0.644; use 0.43
- LSTM feature extraction drives a real browser via Selenium, so it is not real-time
- `phish-stats-globe-main` is standalone and not integrated with the extension
- The extension UI has not been tested for screen-reader or keyboard-only use
- `/check` is unauthenticated and unthrottled — fine for localhost, not for deployment

## License

MIT — see [LICENSE](LICENSE).

---

**Disclaimer**: Educational and research use. Do not rely on this as your only defence against phishing.
