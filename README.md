# Scamify

Scamify is a multi-component project providing real-time phishing risk feedback while browsing.

## Components

### 1. Browser Extension (`Extension/phishing-extension/`)
Injects a lightweight content script that shows a floating tooltip beside any hovered link, displaying the ANN model classification (SAFE / SUSPICIOUS / PHISHING) and confidence.

Features:
- URL extraction heuristics (anchors, data-* attributes, inline text)
- Debounced hover handling with positioning
- Local caching to reduce backend calls
- Backend POST endpoint: `http://127.0.0.1:5000/check`

### 2. Backend (`Extension/backend/`)
Flask service providing:
- `/check` lightweight model inference (for extension)
- `/predict_url` and `/analyze_url` richer endpoints
- Authentication, URL flagging, extension settings (future expansion)
- Loads an ANN model + scaler (see `Extension/ann/`)

### 3. Globe Stats UI (`Extension/phish-stats-globe-main/`)
A separate Vite/TypeScript + Tailwind-based visualization app (potential future integration to show global phishing statistics).

## Repository Layout
```
Extension/
  phishing-extension/    # Chrome extension code
  backend/               # Flask backend (do not commit runtime DB or .env)
  ann/                   # ANN model (.h5) and scaler
  phish-stats-globe-main/ # Globe visualization app (standalone)
```

## Getting Started
### Backend
```bash
cd Extension/backend
python -m venv venv
venv/Scripts/activate  # Windows PowerShell: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Endpoint test:
```bash
curl -X POST http://127.0.0.1:5000/check -H "Content-Type: application/json" -d '{"url":"https://example.com"}'
```

### Extension
1. Open Chrome → `chrome://extensions`.
2. Enable Developer Mode.
3. Load unpacked → select `Extension/phishing-extension`.
4. Hover links on any page — tooltip appears with classification.

### Globe App (optional)
```bash
cd Extension/phish-stats-globe-main/phish-stats-globe-main
npm install
npm run dev
```

## Development Notes
- `.env` and `database.db` are intentionally excluded (.gitignore).
- Model file `optimized_ann_90_9acc.h5` currently tracked (size OK). Consider Git LFS if more/larger models are added.
- Improve security before production: add request auth for `/check` or rate limiting.

## Roadmap Ideas
- Browser storage toggles for enabling/disabling scanning
- Batch pre-scan of visible links
- Suspicious pattern explanations
- Global threat stats overlay integration
- Docker setup for backend

## License
Add a license file (e.g., MIT) before public release.

---
Feel free to contribute by opening issues or PRs once the repository is published.
