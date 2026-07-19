# ThreatLens AI

ThreatLens AI is a Streamlit-based cybersecurity analysis assistant for defensive review of logs and source-code snippets. It combines local rule-based detection with optional Google Gemini enrichment to help analysts identify suspicious patterns, understand impact, and prepare remediation steps.

The application is designed for education, portfolio demonstration, and early security triage. It is not an official Google product.

## What It Does

ThreatLens AI accepts pasted input, uploaded files, or bundled demo samples and produces a structured analysis report. Local detection works without an API key. When a Gemini API key is available, the app can add richer explanations, business impact, executive summaries, and recommended next steps.

The current interface is a compact dark cybersecurity dashboard with three primary areas:

- Home: input upload, input naming, analysis settings, demo data loading, and analysis launch.
- Results: risk score, findings, evidence, remediation, OWASP/MITRE mapping, AI explanation, and report export.
- History: saved analyses from local SQLite storage.

Analysis metadata such as input type, average confidence, Gemini usage, and analysis ID appears in the sidebar after an analysis is complete.

## Main Features

- Local rule-based detection that works without external services
- Optional Gemini enrichment using `gemini-3.5-flash`
- Analysis modes for local scan, Gemini explanation, and full Gemini report
- File upload support for logs, source code, JSON, and config-style text files
- Compact demo data loader for intentionally vulnerable samples
- Risk score from 0 to 100 with severity labeling
- Findings with evidence, confidence, remediation, business impact, and false-positive notes
- OWASP Top 10 and MITRE ATT&CK context where available
- SQLite-backed analysis history
- TXT and JSON report export
- Dark Streamlit dashboard theme

## Detection Coverage

The local detector includes rules for common security signals, including:

- SQL injection
- Cross-site scripting (XSS)
- Brute force activity
- Path traversal
- Command injection
- Suspicious user agents
- Exposed configuration files
- Sensitive file access
- Weak cryptography
- Hardcoded secrets and credentials

Local rules are intended for triage and education. They can produce false positives and should not be treated as a replacement for a full security review.

## Tech Stack

- Python
- Streamlit
- Google Gemini API through `google-genai`
- SQLite
- Pandas
- Regex and rule-based detection
- Streamlit theming and small CSS customizations

The project intentionally avoids a larger web stack. It does not require React, FastAPI, Flask, Docker, Firebase, Supabase, MongoDB, LangChain, authentication, or a vector database.

## Project Structure

```text
threatlensai/
|-- app.py                  Streamlit UI and analysis workflow
|-- gemini_client.py        Gemini prompts, model calls, and JSON parsing
|-- rule_detector.py        Local rule-based detection and evidence capture
|-- risk_scoring.py         Risk score and confidence breakdowns
|-- threat_knowledge.py     OWASP, MITRE, remediation, and impact metadata
|-- report_generator.py     TXT report generation
|-- database.py             SQLite persistence for analysis history
|-- log_parser.py           Apache and generic log parsing
|-- i18n.py                 Translation strings retained for app text
|-- sample_data/            Demo logs and intentionally vulnerable code samples
|-- requirements.txt        Python dependencies for the app
```

At the repository root, `requirements.txt` points Streamlit Cloud to `threatlensai/requirements.txt`.

## Run Locally

From the repository root on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r threatlensai/requirements.txt
streamlit run threatlensai/app.py
```

On macOS or Linux:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r threatlensai/requirements.txt
streamlit run threatlensai/app.py
```

Then open the local Streamlit URL shown in the terminal.

## Gemini API Key

Gemini is optional. Without a key, choose `Local Scan Only` and the app will still run local analysis.

ThreatLens AI reads the Gemini key from either:

1. Streamlit secrets using the name `GEMINI_API_KEY`
2. The sidebar password field for the active session

For Streamlit Cloud, add this in the app secrets panel:

```toml
GEMINI_API_KEY = "your_api_key_here"
```

Do not commit API keys to GitHub. The sidebar field is session-only and is not stored by the app.

If Gemini fails because of a key, quota, model, or service issue, ThreatLens AI falls back to local rule-based results and shows a fallback status in the sidebar.

## Demo Data

The app includes sample data for quick testing:

- Apache logs with suspicious request patterns
- Vulnerable PHP login code
- Vulnerable Flask code

Select an input type, click `Load Demo Data`, then click `Run ThreatLens Analysis`.

## Deploy On Streamlit Community Cloud

1. Push this repository to GitHub.
2. Create a new Streamlit Community Cloud app from the repository.
3. Set the main file path to:

```text
threatlensai/app.py
```

4. Keep the root `requirements.txt` file in place.
5. Optional: add `GEMINI_API_KEY` in the Streamlit secrets panel.
6. Deploy the app.

If no Gemini key is configured, the app still supports local scan and demo workflows.

## Reports

ThreatLens AI can export TXT and JSON reports containing:

- Project name and timestamp
- Analysis mode
- Gemini usage status
- Risk score and severity
- Findings and evidence
- OWASP and MITRE mapping
- Remediation checklist
- Executive summary when available
- Ethical use notice

## Security And Ethics

ThreatLens AI is for defensive security review, education, and authorized analysis only.

Do not use this project for exploitation, live attacks, unauthorized scanning, phishing, malware generation, credential theft, or activity against systems you do not own or have explicit permission to assess.

Findings may be incomplete or include false positives. Validate results before making production changes or incident response decisions.

## Roadmap

- Add more log formats such as Nginx, auth.log, Windows Event exports, and structured JSON logs
- Add SARIF export for security tooling
- Add optional HTML or PDF report export
- Add detector tests and more sample cases
- Add analyst feedback for true-positive and false-positive tracking
