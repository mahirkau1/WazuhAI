from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import storage
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="AegisAI Dashboard")


@app.get("/api/incidents")
def api_incidents():
    return storage.list_incidents(limit=100)


@app.get("/", response_class=HTMLResponse)
def dashboard_home():
    incidents = storage.list_incidents(limit=50)
    rows_html = ""
    for inc in incidents:
        severity_color = {
            "critical": "#ff4d4d", "high": "#ff9800",
            "medium": "#ffd54f", "low": "#8bc34a"
        }.get(inc["severity"], "#ccc")

        remediation = "".join(f"<li>{step}</li>" for step in (inc.get("remediation_steps") or []))
        similar = ", ".join(inc.get("similar_known_attacks") or []) or "\u2014"

        rows_html += f"""
        <div class="card" style="border-left: 6px solid {severity_color}">
            <div class="card-header">
                <span class="badge" style="background:{severity_color}">{inc['severity'].upper()}</span>
                <strong>{inc.get('attack_name') or inc['incident_type']}</strong>
                <span class="risk">Risk: {inc['risk_score']}</span>
            </div>
            <div class="card-body">
                <p><b>Host:</b> {inc['host']} &nbsp; <b>Kullanici:</b> {inc['username']}</p>
                <p><b>Ozet:</b> {inc.get('summary') or 'AI analizi henuz yok (risk esigi altinda kalmis olabilir)'}</p>
                <p><b>Bilinen bir saldiri paterni mi:</b> {'Evet' if inc.get('is_known_pattern') else 'Belirsiz/Hayir'}</p>
                <p><b>Benzer bilinen saldirilar:</b> {similar}</p>
                <p><b>Kapatma adimlari:</b></p>
                <ul>{remediation or '<li>&mdash;</li>'}</ul>
                <p class="timestamp">{inc['created_at']}</p>
            </div>
        </div>
        """

    html = f"""
    <html>
    <head>
        <title>AegisAI Dashboard</title>
        <meta http-equiv="refresh" content="15">
        <style>
            body {{ font-family: -apple-system, sans-serif; background:#0f1117; color:#e6e6e6; padding: 20px; }}
            h1 {{ color: #fff; }}
            .card {{ background:#1a1d27; margin-bottom: 16px; padding: 16px; border-radius: 8px; }}
            .card-header {{ display:flex; align-items:center; gap: 12px; margin-bottom: 8px; }}
            .badge {{ padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight:bold; color:#000; }}
            .risk {{ margin-left:auto; color:#aaa; }}
            .timestamp {{ color:#777; font-size: 12px; }}
            ul {{ margin: 4px 0; padding-left: 20px; }}
        </style>
    </head>
    <body>
        <h1>AegisAI Dashboard</h1>
        <p>Toplam {len(incidents)} incident. Sayfa 15 saniyede bir otomatik yenilenir.</p>
        {rows_html if rows_html else "<p>Henuz incident yok.</p>"}
    </body>
    </html>
    """
    return html


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("DASHBOARD_PORT", 9000))
    uvicorn.run(app, host="0.0.0.0", port=port)
