# ThreatLens AI App

This folder contains the Streamlit application for ThreatLens AI.

## Run

```bash
pip install -r threatlensai/requirements.txt
streamlit run threatlensai/app.py
```

## Main Modules

- `app.py`: Streamlit UI and analysis workflow
- `rule_detector.py`: rule-based detection, evidence capture, and rule confidence
- `threat_knowledge.py`: OWASP, MITRE ATT&CK, remediation, business impact, and recommendation metadata
- `gemini_client.py`: Gemini prompts and response parsing
- `risk_scoring.py`: risk score and score breakdown
- `report_generator.py`: exportable security reports
- `database.py`: SQLite analysis history
- `log_parser.py`: log parsing and statistics
- `sample_data/`: demo Apache logs and intentionally vulnerable code samples

See the repository-level `README.md` for the full project overview, ethical notice, and roadmap.
