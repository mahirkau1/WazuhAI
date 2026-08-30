#  VELNOX 

VELNOX is a defensive SOC / endpoint security project that reads Wazuh alerts, normalizes Windows telemetry, applies local detection and correlation rules, stores incidents in SQLite, and presents the results in a FastAPI dashboard. Higher-risk incidents can optionally be enriched with an AI-assisted analysis.

> **Status:** Development / lab project. AegisAI is not a replacement for a production SIEM, EDR, incident-response process, or analyst validation.

## Features

- Wazuh Indexer alert ingestion
- Windows / Sysmon event normalization
- Rule-based incident detection and correlation
- Risk scoring and severity classification
- SQLite-backed event and incident history
- MITRE ATT&CK metadata support when present in telemetry/rules
- FastAPI web dashboard
- Optional Anthropic-based incident analysis
- Environment-variable based secret handling

## Architecture

```text
Windows / Sysmon
      │
      ▼
    Wazuh
      │
      ▼
Wazuh Indexer
      │
      ▼
 wazuh_client.py
      │
      ▼
 normalize.py ──► rules.py
      │              │
      └──────┬───────┘
             ▼
          agent.py
          │      │
          ▼      ▼
     storage.py  ai_engine.py (optional enrichment)
          │
          ▼
       aegis.db
          │
          ▼
     dashboard.py
```

## Repository layout

```text
AegisAgent/
├── app/
│   ├── agent.py
│   ├── ai_engine.py
│   ├── dashboard.py
│   ├── normalize.py
│   ├── rules.py
│   ├── storage.py
│   └── wazuh_client.py
├── .env.example
├── .gitignore
├── requirements.txt
├── setup.sh
├── SECURITY.md
└── README.md
```

Runtime files such as `.env`, virtual environments, Python caches, logs and SQLite databases are intentionally excluded from Git.

## Requirements

- Python 3.10+
- A reachable Wazuh Indexer
- Windows/Sysmon telemetry forwarded to Wazuh for the detections you want to evaluate
- Anthropic API key only if AI-assisted analysis is enabled by the current code path

## Quick start — Windows PowerShell

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and provide your own Wazuh connection details and API key. Never commit `.env`.

Run the agent:

```powershell
.\venv\Scripts\Activate.ps1
cd app
python .\agent.py
```

In a second terminal, run the dashboard:

```powershell
.\venv\Scripts\Activate.ps1
cd app
python .\dashboard.py
```

Then open `http://localhost:9000` on the machine running the dashboard.

## Quick start — Linux

```bash
chmod +x setup.sh
./setup.sh
nano .env
```

Run the agent:

```bash
source venv/bin/activate
cd app
python agent.py
```

Run the dashboard in another terminal:

```bash
source venv/bin/activate
cd app
python dashboard.py
```

## Configuration

| Variable | Purpose | Example |
|---|---|---|
| `WAZUH_INDEXER_URL` | Wazuh Indexer HTTPS endpoint | `https://localhost:9200` |
| `WAZUH_INDEXER_USER` | Indexer username | `admin` |
| `WAZUH_INDEXER_PASSWORD` | Indexer password | `CHANGE_ME` |
| `ANTHROPIC_API_KEY` | Optional AI analysis credential | `CHANGE_ME` |
| `AI_RISK_THRESHOLD` | Minimum risk score for AI analysis | `60` |
| `POLL_INTERVAL_SECONDS` | Agent polling interval | `30` |
| `DASHBOARD_PORT` | Dashboard port | `9000` |

## Security notes

- Never commit `.env`, credentials, API keys, production logs, or `aegis.db`.
- Use a dedicated least-privilege Wazuh Indexer account instead of a privileged administrator account in real deployments.
- The current dashboard is intended for a trusted lab/internal environment. Do not expose it directly to the public internet without authentication, TLS, network restrictions, and a production deployment configuration.
- The Wazuh client currently supports self-signed lab certificates. For production, use proper certificate validation.
- Treat AI output as analyst assistance, not an authoritative incident verdict.

See [SECURITY.md](SECURITY.md) for responsible reporting and deployment guidance.

## Testing

A basic syntax check can be run with:

```bash
python -m py_compile app/*.py
```

For security testing, use only systems you own or are explicitly authorized to test. Controlled lab telemetry (for example, Atomic Red Team tests) can be used to validate detections.

## Roadmap

Planned areas include richer attack-story visualization, process/entity relationships, explainable UEBA baselines, MITRE coverage views, and additional defensive correlation rules.

