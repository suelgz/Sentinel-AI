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

- Python 3.12
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

Deployment-related files live at the repository root:

```text
railway.json              Railway start command and Railpack builder config
.python-version           Python runtime hint for Railway
requirements.txt          Python dependencies for Railway and local installs
.gitignore                Local secrets, runtime data, and generated files
```

## Run Locally

From the repository root on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run threatlensai/app.py
```

On macOS or Linux:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run threatlensai/app.py
```

Then open the local Streamlit URL shown in the terminal.

## Railway Deployment

This repository is prepared for Railway using a single `railway.json` file. Railway should run the Streamlit app with the platform-provided `PORT` variable and bind the server to `0.0.0.0`.

Final Railway start command:

```bash
streamlit run threatlensai/app.py --server.address 0.0.0.0 --server.port $PORT --server.headless true
```

Manual deployment flow:

1. Review the local changes.
2. Commit and push them to GitHub.
3. Create a Railway project.
4. Choose `Deploy from GitHub Repo`.
5. Select this repository.
6. Configure environment variables if needed.
7. Confirm Railway is using the start command above, or enter it manually.
8. Deploy the service.
9. Generate a public Railway domain.
10. Test the app, including local-only analysis, optional Gemini analysis, history, and report export.

Railway provides `PORT` automatically. Do not hardcode a port in the application or set a fixed port unless you intentionally override Railway's default behavior.

## Gemini API Key

Gemini is optional. Without a key, choose `Local Scan Only` and the app will still run local analysis.

ThreatLens AI reads the Gemini key from either:

1. The environment variable `GEMINI_API_KEY`
2. The sidebar password field for the active session

For Railway, add `GEMINI_API_KEY` as a service variable only if you want server-side Gemini support. Do not commit API keys to GitHub. The sidebar field is session-only and is not stored by the app.

If Gemini fails because of a key, quota, model, or service issue, ThreatLens AI falls back to local rule-based results and shows a fallback status in the sidebar.

## Persistence On Railway

ThreatLens AI stores analysis history in SQLite and can generate report text for downloads. On Railway, the local filesystem should be treated as ephemeral unless you configure a persistent volume.

By default, the app can still create and use its SQLite database and runtime folders inside the running container, but that data may disappear after redeployments, restarts, or container replacement.

Optional environment variables for custom storage paths:

- `THREATLENSAI_STATE_DIR`: directory used for runtime state when no explicit DB path is set
- `THREATLENSAI_DB_PATH`: exact SQLite database path
- `THREATLENSAI_EXPORTS_DIR`: directory for saved report files if `save_text_report` is used

Do not set these to paths outside Railway's writable filesystem. If long-term history is required, configure a Railway volume or migrate storage later; this migration does not introduce a new database service.

## Demo Data

The app includes sample data for quick testing:

- Apache logs with suspicious request patterns
- Vulnerable PHP login code
- Vulnerable Flask code

Select an input type, click `Load Demo Data`, then click `Run ThreatLens Analysis`.

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
