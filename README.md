# Phish Sense: Context-Aware Scam Detection System

Phish Sense is now available in two modes:
- Streamlit web app (model + rule engine)
- Browser-side realtime scanner (Chrome extension + Tampermonkey userscript)

## Key Features
- Multi-class detection labels: `phishing`, `otp_scam`, `job_scam`, `lottery`, `safe`
- Risk score (0-100)
- Explainable reasons and highlighted suspicious patterns
- URL safety checks (shorteners, suspicious domains, obfuscated links)
- Realtime page assessment for dynamic websites

## Project Structure
```text
project/
|-- app.py
|-- train.py
|-- inference.py
|-- requirements.txt
|-- data/
|   `-- dataset.csv
|-- model/
|   `-- model.pkl
|-- utils/
|   |-- preprocessing.py
|   |-- rules.py
|   `-- url_checker.py
|-- browser-extension/
|   |-- manifest.json
|   |-- background.js
|   |-- content.js
|   |-- popup.html
|   |-- popup.css
|   |-- popup.js
|   `-- README.md
`-- userscript/
    `-- phish-sense.user.js
```

## A) Run ML + Rule Engine (Streamlit)
```bash
python -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install --upgrade pip
.\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt

.\\.venv\\Scripts\\python.exe train.py
.\\.venv\\Scripts\\python.exe -m streamlit run app.py
```

## B) Chrome Extension (Realtime)
1. Open `chrome://extensions/`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select `project/browser-extension`
5. Browse normally: risk widget appears on pages automatically

## C) Tampermonkey / GreasyFork-style Userscript
1. Install Tampermonkey extension
2. Create new script and paste content of:
   - `project/userscript/phish-sense.user.js`
3. Save and refresh target pages

## CLI Inference Example
```bash
.\\.venv\\Scripts\\python.exe inference.py --text "Urgent verify account now at http://bit.ly/abc123"
```

## Sample JSON Output
```json
{
  "prediction": "phishing",
  "risk_score": 82,
  "reasons": ["Urgency detected", "Suspicious URL found"],
  "highlighted_words": ["urgent", "verify"],
  "url_flag": "Suspicious"
}
```

## Notes
- Dataset size: 293 labeled samples
- Lightweight by design for low-resource machines
- Browser scanner is heuristic/context-driven and should be used with standard browser security protections
