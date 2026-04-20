# Phish Sense: Context-Aware Scam Detection System

Lightweight hybrid NLP mini-project for low-resource machines (CPU-friendly).

## Features
- Multi-class classification: `phishing`, `otp_scam`, `job_scam`, `lottery`, `safe`
- Risk score (0-100) using hybrid fusion:
  - `Final Score = 0.6 * ML Score + 0.4 * Rule Score`
- Explainability via suspicious word highlighting + reason list
- URL extraction and safety flagging
- Streamlit UI

## Project Structure
```text
project/
|-- data/
|   `-- dataset.csv
|-- model/
|   `-- model.pkl   (generated after training)
|-- utils/
|   |-- preprocessing.py
|   |-- rules.py
|   `-- url_checker.py
|-- train.py
|-- inference.py
|-- app.py
|-- sample_outputs.json
`-- requirements.txt
```

## Setup
```bash
pip install -r requirements.txt
```

## Train
```bash
python train.py
```

## Inference (CLI)
```bash
python inference.py --text "Urgent! Verify your SBI account now at http://bit.ly/abc123"
```

## Run UI
```bash
streamlit run app.py
```

## Sample Output Format
```json
{
  "prediction": "phishing",
  "risk_score": 82,
  "reasons": ["Urgency detected", "Suspicious URL found"],
  "highlighted_words": ["urgent", "verify", "http://bit.ly/abc123"],
  "url_flag": "Suspicious"
}
```

## Notes
- Training set size: 293 labeled samples
- Model: TF-IDF + Logistic Regression
- Built to stay lightweight and fast on CPU-only environments
