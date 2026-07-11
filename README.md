# ThreatLens AI

ThreatLens AI is a focused Streamlit cybersecurity analysis assistant. It reviews logs and source-code snippets with a local regex/rule-based detector, then optionally uses Google Gemini API to explain findings, summarize risk, and suggest remediation.

Built as a student cybersecurity AI project using Google Gemini API. Designed for defensive security education, early triage, and portfolio demonstration. Suitable for BTK Akademi / Google / Girişimcilik Vakfı style AI and entrepreneurship applications.

This is not an official Google product.

## Main Features

- Modern Streamlit interface with cyber/AI themed dashboard cards and analysis tabs
- Local analysis works without any API key
- Optional Gemini enrichment for executive summaries, technical explanations, business impact, false-positive notes, and remediation advice
- Analysis modes:
  - Local Scan Only
  - Local + Gemini Explanation
  - Full Gemini Report
- English/Turkish language selector
- Demo Mode with intentionally vulnerable Apache logs, PHP login code, and Flask code
- Overall risk score from 0 to 100 with severity explanation and top risk factors
- Findings mapped to OWASP Top 10 and MITRE ATT&CK when available
- SQLite history for previous analyses
- JSON and TXT report export

## Minimal Tech Stack

- Python
- Streamlit
- Google Gemini API
- SQLite
- Regex/rule-based local detection
- JSON/TXT report export
- Basic CSS inside Streamlit

No FastAPI, Flask, React, Firebase, Supabase, MongoDB, LangChain, vector database, Docker, or authentication system is required.

## Local Detection Coverage

ThreatLens AI includes rule-based support for:

- SQL Injection
- XSS
- Brute Force
- Path Traversal
- Command Injection
- Suspicious User-Agent
- Exposed Config Files
- Sensitive File Access
- Weak Cryptography
- Hardcoded Secrets / Credentials

Each finding can include threat type, severity, confidence, evidence, explanation, remediation, OWASP mapping, MITRE ATT&CK mapping, business impact, and false-positive notes.

## Project Structure

```text
threatlensai/
|-- app.py                  Streamlit app and UI workflow
|-- gemini_client.py        Gemini prompts, JSON parsing, and fallback-safe calls
|-- rule_detector.py        Regex/rule-based threat detection
|-- risk_scoring.py         0-100 risk scoring
|-- report_generator.py     TXT report generation
|-- database.py             SQLite history storage
|-- threat_knowledge.py     OWASP, MITRE, remediation, and impact metadata
|-- log_parser.py           Apache/generic log parsing
|-- i18n.py                 English/Turkish UI strings
|-- sample_data/            Demo log and vulnerable code samples
|-- requirements.txt        App dependencies
```

## How To Run Locally

From the repository root:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run threatlensai/app.py
```

On macOS/Linux:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run threatlensai/app.py
```

Gemini API key is optional. Without a key, choose `Local Scan Only` or load Demo Mode and run local analysis.

## Gemini API Key

ThreatLens AI loads the Gemini key from:

1. Streamlit secrets: `GEMINI_API_KEY`
2. The sidebar password input field

Do not commit API keys to GitHub. The sidebar key is used only for the active Streamlit session and is not stored by the app.

Gemini is used to enrich local findings, not replace them. If Gemini fails, the app falls back to local rule-based results.

## Demo Mode

Demo Mode works without a Gemini API key. It includes:

- Apache access log with SQL injection, XSS, brute force, path traversal, command injection, exposed config, and scanner examples
- Vulnerable PHP login code
- Vulnerable Flask snippet

Use `Load Demo Data`, then `Run ThreatLens Analysis`.

## Streamlit Community Cloud Deployment

1. Push this repository to GitHub.
2. In Streamlit Community Cloud, create a new app from the repository.
3. Set the main file path to:

```text
threatlensai/app.py
```

4. Keep dependencies in `requirements.txt` at the repository root. It points to `threatlensai/requirements.txt`.
5. Optional: add `GEMINI_API_KEY` in Streamlit app secrets.
6. Deploy the app.

If no Gemini secret is configured, users can still run local/demo analysis.

## Report Export

Reports include:

- Project name and timestamp
- Analysis mode
- Whether Gemini was used
- Overall risk score and severity
- Findings and evidence
- OWASP and MITRE mapping
- Remediation checklist
- Executive summary
- Ethical notice

TXT and JSON exports are supported. PDF export is intentionally left for the roadmap unless a stable implementation is added later.

## Ethical Notice

ThreatLens AI is for defensive security review, education, and authorized analysis only.

Do not use this project for exploitation, live attacks, unauthorized scanning, phishing, malware generation, credential theft, or activity against systems you do not own or have explicit permission to assess.

Findings may include false positives. Validate results before production changes or incident response decisions.

