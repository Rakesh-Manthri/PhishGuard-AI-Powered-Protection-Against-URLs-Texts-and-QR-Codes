# Website + PhishGuard (local dev)

This workspace contains a small frontend (static HTML/JS), a Node chat server, and a lightweight Python PhishGuard API for phishing detection.

Quick run (recommended):

- Serve frontend: `npm run serve-web` → http://localhost:5500
- Start chat server: `npm run start-node` → http://localhost:3000
- Start API: (in a Python venv) `uvicorn api.app:app --reload --port 8000` → http://localhost:8000

Or run services in separate terminals. See `api/README.md` for Python setup.

## Dev helpers (new)
- Start frontend + API (single command):
  - `npm run dev`  — runs `tools/dev-start.ps1` (starts frontend & API, opens browser)
- Train local text model (uses scikit-learn):
  - `npm run train`  — runs `PhishGuard/train_text_model.py` and writes `PhishGuard/models/text_model.joblib`

## How to train and verify
1. Create & activate Python venv and install deps:
   - `python -m venv .venv; .\.venv\Scripts\Activate; pip install -r PhishGuard/requirements.txt`
2. Train (small example dataset included):
   - `python PhishGuard/train_text_model.py` (or `npm run train`)
3. Verify model is loaded by the API:
   - `curl http://127.0.0.1:8000/health` → `"local_model_loaded": true` when a model is present
4. Run an end-to-end scan from the UI (ensure "Use server scan" is checked) or call:
   - `curl -X POST http://127.0.0.1:8000/phishguard/scan -d '{"text":"Your account is locked!"}' -H 'Content-Type: application/json'`

