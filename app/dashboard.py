from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import storage
import os
from dotenv import load_dotenv

load_dotenv(override=True)

app = FastAPI(title="VELNOX Dashboard")


@app.get("/api/incidents")
def api_incidents():
    return storage.list_incidents(limit=300)


@app.get("/api/incidents/{incident_id}/events")
def api_incident_events(incident_id: int):
    return storage.get_incident_events(incident_id)


@app.get("/api/incidents/{incident_id}/visualization")
def api_incident_visualization(incident_id: int):
    # Yeni storage surumunde hazir visualization fonksiyonunu kullan.
    if hasattr(storage, "get_incident_visualization"):
        return storage.get_incident_visualization(incident_id)

    # Geriye donuk uyumluluk: eski storage.py ile dashboard yine acilsin.
    events = storage.get_incident_events(incident_id)
    story = []
    for idx, event in enumerate(events, start=1):
        event_type = event.get("event_type") or "event"
        category = "other"
        low = event_type.lower()
        for key in ("process", "network", "dns", "registry", "file", "auth"):
            if key in low:
                category = "authentication" if key == "auth" else key
                break
        story.append({
            "step": idx,
            "timestamp": event.get("timestamp"),
            "category": category,
            "event_type": event_type,
            "event_id": event.get("event_id"),
            "host": event.get("host"),
            "username": event.get("username"),
            "process": event.get("process"),
            "command_line": event.get("command_line"),
            "destination_ip": event.get("destination_ip"),
            "destination_port": event.get("destination_port"),
            "dns_query": event.get("dns_query"),
            "target_filename": event.get("target_filename"),
            "registry_target": event.get("registry_target"),
        })

    nodes = {}
    roots = []
    for event in events:
        pid = event.get("process_id")
        guid = event.get("process_guid")
        if not pid and not guid:
            continue
        key = f"guid:{guid}" if guid else f"pid:{event.get('host')}:{pid}"
        nodes.setdefault(key, {
            "key": key,
            "process_id": pid,
            "process_guid": guid,
            "image": event.get("process"),
            "command_line": event.get("command_line"),
            "parent_process_id": event.get("parent_process_id"),
            "parent_process_guid": event.get("parent_process_guid"),
            "children": [],
            "synthetic": False,
        })

    for key, node in list(nodes.items()):
        parent_key = None
        if node.get("parent_process_guid"):
            parent_key = f"guid:{node['parent_process_guid']}"
        elif node.get("parent_process_id"):
            parent_key = f"pid:{events[0].get('host') if events else ''}:{node['parent_process_id']}"
        if parent_key and parent_key in nodes and parent_key != key:
            if key not in nodes[parent_key]["children"]:
                nodes[parent_key]["children"].append(key)
        else:
            roots.append(key)

    return {
        "incident_id": incident_id,
        "attack_story": story,
        "process_tree": {
            "roots": roots,
            "nodes": nodes,
            "node_count": len(nodes),
            "edge_count": sum(len(n.get("children", [])) for n in nodes.values()),
        },
    }


@app.get("/", response_class=HTMLResponse)
def dashboard_home():
    return HTML_PAGE


HTML_PAGE = """
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VELNOX &mdash; Security Operations Dashboard</title>
<style>
    :root {
        --bg: #08090d;
        --bg-elevated: #0f1117;
        --card-bg: #12141c;
        --card-bg-hover: #161925;
        --border: #1f2330;
        --border-soft: #1a1d28;
        --text: #eef0f5;
        --text-dim: #8a90a4;
        --text-faint: #565c70;
        --critical: #ff4757;
        --critical-soft: #ff475720;
        --high: #ffa53d;
        --high-soft: #ffa53d20;
        --medium: #ffd93d;
        --medium-soft: #ffd93d20;
        --low: #3ddc84;
        --low-soft: #3ddc8420;
        --accent: #5b8cff;
        --accent-soft: #5b8cff20;
        --purple: #a78bfa;
        --radius: 12px;
        --radius-sm: 8px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
        background:
            radial-gradient(ellipse 1200px 600px at 20% -10%, #1a1030 0%, transparent 60%),
            radial-gradient(ellipse 1000px 500px at 100% 0%, #0d1a30 0%, transparent 60%),
            var(--bg);
        color: var(--text);
        min-height: 100vh;
        -webkit-font-smoothing: antialiased;
    }

    /* ============ HEADER ============ */
    header {
        position: sticky; top: 0; z-index: 50;
        background: #08090dee;
        backdrop-filter: blur(16px) saturate(1.5);
        border-bottom: 1px solid var(--border-soft);
        padding: 16px 32px;
        display: flex; align-items: center; gap: 16px;
    }
    .logo { display: flex; align-items: center; gap: 10px; }
    .logo-icon {
        width: 34px; height: 34px; border-radius: 9px;
        background: linear-gradient(135deg, #5b8cff, #a78bfa);
        display: flex; align-items: center; justify-content: center;
        font-size: 17px; box-shadow: 0 0 20px #5b8cff40;
    }
    .logo-text { font-size: 17px; font-weight: 700; letter-spacing: -0.02em; }
    .logo-sub { font-size: 11px; color: var(--text-faint); font-weight: 500; }

    .header-right { margin-left: auto; display: flex; align-items: center; gap: 18px; }
    .live-indicator { display: flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--text-dim); }
    .live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--low); box-shadow: 0 0 8px var(--low); animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1; transform:scale(1);} 50%{opacity:.4; transform:scale(0.8);} }

    .search-box {
        background: var(--card-bg); border: 1px solid var(--border);
        border-radius: 20px; padding: 7px 16px; font-size: 13px;
        color: var(--text); width: 220px; outline: none; transition: all .15s;
    }
    .search-box:focus { border-color: var(--accent); width: 280px; }
    .search-box::placeholder { color: var(--text-faint); }

    /* ============ LAYOUT ============ */
    .container { max-width: 1320px; margin: 0 auto; padding: 28px 32px 60px; }

    /* ============ STAT CARDS ============ */
    .stats-grid {
        display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 14px; margin-bottom: 24px;
    }
    .stat-card {
        background: var(--card-bg); border: 1px solid var(--border-soft);
        border-radius: var(--radius); padding: 18px 20px;
        position: relative; overflow: hidden; transition: transform .15s, border-color .15s;
    }
    .stat-card:hover { transform: translateY(-2px); border-color: var(--border); }
    .stat-card::before {
        content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
        background: var(--accent-color, var(--accent));
    }
    .stat-label { font-size: 11.5px; color: var(--text-faint); text-transform: uppercase; letter-spacing: .06em; font-weight: 600; margin-bottom: 8px; }
    .stat-value { font-size: 30px; font-weight: 700; letter-spacing: -0.02em; line-height: 1; }
    .stat-value small { font-size: 14px; color: var(--text-faint); font-weight: 500; }

    /* ============ CHARTS ROW ============ */
    .charts-grid {
        display: grid; grid-template-columns: 1.1fr 1.4fr 1fr; gap: 14px; margin-bottom: 28px;
    }
    @media (max-width: 900px) { .charts-grid { grid-template-columns: 1fr; } }
    .chart-card {
        background: var(--card-bg); border: 1px solid var(--border-soft);
        border-radius: var(--radius); padding: 20px;
    }
    .chart-title {
        font-size: 12.5px; font-weight: 600; color: var(--text-dim);
        text-transform: uppercase; letter-spacing: .05em; margin-bottom: 16px;
        display: flex; align-items: center; justify-content: space-between;
    }
    .donut-wrap { display: flex; align-items: center; gap: 20px; }
    .donut-legend { display: flex; flex-direction: column; gap: 8px; font-size: 12.5px; flex: 1; }
    .legend-row { display: flex; align-items: center; gap: 8px; color: var(--text-dim); }
    .legend-dot { width: 9px; height: 9px; border-radius: 3px; flex-shrink: 0; }
    .legend-row b { color: var(--text); margin-left: auto; font-weight: 600; }

    .mitre-bars { display: flex; flex-direction: column; gap: 10px; }
    .mitre-bar-row { display: grid; grid-template-columns: 90px 1fr 24px; align-items: center; gap: 10px; font-size: 12px; }
    .mitre-bar-label { color: var(--text-dim); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .mitre-bar-track { height: 7px; background: var(--border-soft); border-radius: 4px; overflow: hidden; }
    .mitre-bar-fill { height: 100%; border-radius: 4px; background: linear-gradient(90deg, var(--accent), var(--purple)); }
    .mitre-bar-count { color: var(--text-faint); text-align: right; font-variant-numeric: tabular-nums; }

    .timeline-svg { width: 100%; height: 90px; }

    /* ============ FILTERS ============ */
    .filters-row {
        display: flex; align-items: center; gap: 8px; margin-bottom: 18px; flex-wrap: wrap;
    }
    .filter-btn {
        background: var(--card-bg); border: 1px solid var(--border-soft); color: var(--text-dim);
        padding: 7px 16px; border-radius: 20px; cursor: pointer; font-size: 12.5px;
        font-weight: 600; transition: all .15s; display: flex; align-items: center; gap: 6px;
    }
    .filter-btn:hover { border-color: var(--border); color: var(--text); }
    .filter-btn.active { background: var(--text); color: var(--bg); border-color: var(--text); }
    .filter-count { font-size: 10.5px; opacity: .7; }

    /* ============ INCIDENT CARDS ============ */
    #incidents { display: flex; flex-direction: column; gap: 10px; }
    .empty-state { text-align: center; color: var(--text-faint); padding: 100px 20px; font-size: 14px; }

    .card {
        background: var(--card-bg); border: 1px solid var(--border-soft);
        border-radius: var(--radius); overflow: hidden;
        transition: border-color .15s, background .15s;
    }
    .card:hover { border-color: var(--border); background: var(--card-bg-hover); }
    .card-head {
        padding: 15px 20px; display: flex; align-items: center; gap: 12px;
        cursor: pointer; flex-wrap: wrap;
    }
    .sev-strip { width: 4px; align-self: stretch; border-radius: 2px; flex-shrink: 0; }
    .badge {
        font-size: 10.5px; font-weight: 700; padding: 3px 9px; border-radius: 5px;
        text-transform: uppercase; letter-spacing: .04em; flex-shrink: 0;
    }
    .sev-critical { background: var(--critical-soft); color: var(--critical); }
    .sev-high { background: var(--high-soft); color: var(--high); }
    .sev-medium { background: var(--medium-soft); color: var(--medium); }
    .sev-low { background: var(--low-soft); color: var(--low); }
    .occ-badge { background: var(--accent-soft); color: var(--accent); }
    .fp-badge-inline { background: var(--border-soft); color: var(--text-faint); }

    .attack-name { font-weight: 600; font-size: 14.5px; flex: 1; min-width: 200px; }
    .card-meta-inline { font-size: 12px; color: var(--text-faint); white-space: nowrap; }
    .risk-pill {
        font-size: 12px; font-weight: 700; padding: 3px 10px; border-radius: 20px;
        background: var(--border-soft); color: var(--text-dim); font-variant-numeric: tabular-nums;
    }
    .chevron { color: var(--text-faint); transition: transform .2s; font-size: 11px; }
    .card.open .chevron { transform: rotate(90deg); }

    .card-body { display: none; padding: 4px 20px 20px 20px; }
    .card.open .card-body { display: block; }

    .meta-row {
        display: grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr));
        gap: 10px; font-size: 12px; color: var(--text-faint);
        background: var(--bg-elevated); border-radius: var(--radius-sm); padding: 12px 14px; margin-bottom: 16px;
    }
    .meta-row div b { display: block; color: var(--text); font-size: 13px; font-weight: 600; margin-top: 2px; }

    .section { margin: 16px 0; }
    .section h4 {
        margin: 0 0 8px; font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
        color: var(--text-faint); font-weight: 700; display:flex; align-items:center; gap:8px;
    }
    .section p { margin: 0; font-size: 13.5px; line-height: 1.6; color: #d4d7e2; }
    .section ul { margin: 4px 0 0; padding-left: 18px; font-size: 13.5px; line-height: 1.75; color: #d4d7e2; }
    .section ul li::marker { color: var(--accent); }

    .mitre-chip {
        display: inline-flex; align-items: center; gap: 6px;
        background: var(--accent-soft); border: 1px solid #5b8cff30; color: #9db4ff;
        padding: 5px 11px; border-radius: 7px; font-size: 12px; margin: 3px 6px 3px 0;
        text-decoration: none; font-weight: 500; transition: all .15s;
    }
    .mitre-chip:hover { background: #5b8cff35; border-color: #5b8cff60; }

    .ai-pending { color: var(--text-faint); font-style: italic; font-size: 13px; }
    .ai-error {
        color: var(--critical); font-size: 13px; background: var(--critical-soft);
        padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid #ff475730;
    }

    .fp-tag { font-size: 10.5px; padding: 2px 9px; border-radius: 10px; font-weight: 600; }
    .fp-low { background: var(--low-soft); color: var(--low); }
    .fp-medium { background: var(--medium-soft); color: var(--medium); }
    .fp-high { background: var(--critical-soft); color: var(--critical); }

    .divider { height: 1px; background: var(--border-soft); margin: 16px 0; }


    /* ============ ATTACK STORY + PROCESS TREE ============ */
    .visual-grid { display:grid; grid-template-columns:1.35fr 1fr; gap:14px; margin-top:16px; }
    @media (max-width: 900px) { .visual-grid { grid-template-columns:1fr; } }
    .visual-card { background:var(--bg-elevated); border:1px solid var(--border-soft); border-radius:var(--radius-sm); padding:15px; min-height:150px; }
    .visual-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:14px; }
    .visual-title { font-size:11px; text-transform:uppercase; letter-spacing:.07em; color:var(--text-faint); font-weight:700; }
    .visual-kpi { font-size:10.5px; color:var(--text-faint); background:var(--card-bg); border:1px solid var(--border-soft); padding:4px 8px; border-radius:999px; }
    .viz-loading,.viz-empty { color:var(--text-faint); font-size:12.5px; padding:24px 4px; text-align:center; }

    .story-track { position:relative; display:flex; flex-direction:column; gap:0; padding-left:7px; }
    .story-track::before { content:""; position:absolute; left:15px; top:9px; bottom:10px; width:1px; background:linear-gradient(var(--accent),#a78bfa40); }
    .story-item { position:relative; display:grid; grid-template-columns:30px 1fr; gap:10px; padding:0 0 14px; }
    .story-node { width:18px; height:18px; border-radius:50%; margin-top:2px; z-index:1; background:var(--card-bg); border:2px solid var(--story-color,var(--accent)); box-shadow:0 0 0 4px var(--bg-elevated); display:flex; align-items:center; justify-content:center; font-size:8px; }
    .story-content { min-width:0; }
    .story-top { display:flex; align-items:center; gap:7px; flex-wrap:wrap; }
    .story-name { font-size:12.5px; color:var(--text); font-weight:600; }
    .story-time { font-size:10.5px; color:var(--text-faint); margin-left:auto; }
    .story-detail { font-size:11.5px; color:var(--text-dim); margin-top:4px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .story-cat { font-size:9.5px; text-transform:uppercase; letter-spacing:.05em; padding:2px 6px; border-radius:5px; background:var(--accent-soft); color:#9db4ff; }

    .tree-canvas { overflow:auto; padding:3px 2px 2px; }
    .tree-root { display:flex; flex-direction:column; align-items:flex-start; gap:10px; min-width:260px; }
    .tree-branch { position:relative; padding-left:25px; margin-left:10px; display:flex; flex-direction:column; gap:10px; }
    .tree-branch::before { content:""; position:absolute; left:7px; top:-8px; bottom:16px; width:1px; background:#34394a; }
    .tree-wrap { position:relative; }
    .tree-wrap::before { content:""; position:absolute; left:-18px; top:18px; width:18px; height:1px; background:#34394a; }
    .tree-node { display:flex; align-items:center; gap:9px; background:var(--card-bg); border:1px solid var(--border); border-radius:9px; padding:8px 10px; max-width:360px; transition:.15s; }
    .tree-node:hover { border-color:#5b8cff60; transform:translateX(2px); }
    .tree-icon { width:25px; height:25px; border-radius:7px; background:linear-gradient(135deg,#5b8cff24,#a78bfa24); border:1px solid #5b8cff30; display:flex; align-items:center; justify-content:center; flex-shrink:0; font-size:11px; }
    .tree-main { min-width:0; flex:1; }
    .tree-name { font-size:11.5px; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .tree-meta { font-size:9.5px; color:var(--text-faint); margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .tree-synthetic { opacity:.65; border-style:dashed; }
    .tree-stats { display:flex; gap:6px; }

    ::-webkit-scrollbar { width: 10px; height: 10px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 5px; }
</style>
</head>
<body>

<header>
    <div class="logo">
        <div class="logo-icon">&#128737;</div>
        <div>
            <div class="logo-text">VELNOX</div>
            <div class="logo-sub">Security Operations Dashboard</div>
        </div>
    </div>
    <div class="header-right">
        <input class="search-box" id="search" type="text" placeholder="Ara: host, kullanici, MITRE, saldiri adi...">
        <div class="live-indicator"><span class="live-dot"></span><span id="last-updated">yukleniyor...</span></div>
    </div>
</header>

<div class="container">

    <div class="stats-grid" id="stats-grid"></div>

    <div class="charts-grid">
        <div class="chart-card">
            <div class="chart-title">Severity Dagilimi</div>
            <div class="donut-wrap">
                <svg id="donut-svg" width="110" height="110" viewBox="0 0 110 110"></svg>
                <div class="donut-legend" id="donut-legend"></div>
            </div>
        </div>
        <div class="chart-card">
            <div class="chart-title">En Sik Gorulen MITRE Teknikleri</div>
            <div class="mitre-bars" id="mitre-bars"></div>
        </div>
        <div class="chart-card">
            <div class="chart-title">Son 24 Saat &mdash; Olay Yogunlugu</div>
            <svg class="timeline-svg" id="timeline-svg" viewBox="0 0 300 90"></svg>
        </div>
    </div>

    <div class="filters-row" id="filters-row"></div>

    <div id="incidents"><div class="empty-state">Yukleniyor...</div></div>
</div>

<script>
let currentFilter = "all";
let searchTerm = "";
let incidentsCache = [];
const visualizationCache = new Map();
const visualizationLoading = new Set();

function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, ch => ({
        "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
    })[ch]);
}
function basename(path) {
    if (!path) return "Bilinmeyen process";
    const clean = String(path).replace(/\\\\/g, "/");
    return clean.split("/").pop() || clean;
}

const SEV_COLORS = { critical: "#ff4757", high: "#ffa53d", medium: "#ffd93d", low: "#3ddc84" };
const SEV_ORDER = ["critical", "high", "medium", "low"];

function mitreLink(m) {
    const id = m.technique_id || m.id || "";
    const name = m.technique_name || m.technique || "";
    const tactic = m.tactic || "";
    const label = id + (name ? (" - " + name) : "");
    const url = "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/";
    return `<a class="mitre-chip" href="${esc(url)}" target="_blank" rel="noopener noreferrer" title="${esc(tactic)}">&#127919; ${esc(label)}</a>`;
}

function fpBadge(level) {
    if (!level) return "";
    const cls = level === "low" ? "fp-low" : (level === "medium" ? "fp-medium" : "fp-high");
    const label = level === "low" ? "Gercek olabilir" : (level === "medium" ? "Belirsiz" : "Muhtemelen test/FP");
    return `<span class="fp-tag ${cls}">${label}</span>`;
}

function timeAgo(dateStr) {
    if (!dateStr) return "-";
    const d = new Date(dateStr.replace(" ", "T") + "Z");
    const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
    if (diffSec < 60) return diffSec + "sn once";
    if (diffSec < 3600) return Math.floor(diffSec/60) + "dk once";
    if (diffSec < 86400) return Math.floor(diffSec/3600) + "sa once";
    return Math.floor(diffSec/86400) + "gun once";
}

// ============ ISTATISTIK KARTLARI ============
function renderStats() {
    const total = incidentsCache.length;
    const critical = incidentsCache.filter(i => i.severity === "critical").length;
    const avgRisk = total ? Math.round(incidentsCache.reduce((s,i)=>s+i.risk_score,0)/total) : 0;
    const totalOccurrences = incidentsCache.reduce((s,i)=>s+(i.occurrence_count||1), 0);
    const uniqueMitre = new Set();
    incidentsCache.forEach(i => (i.mitre && i.mitre.length ? i.mitre : (i.rule_mitre||[])).forEach(m => uniqueMitre.add(m.technique_id||m.id)));
    const aiAnalyzed = incidentsCache.filter(i => i.attack_name).length;

    const cards = [
        { label: "Toplam Incident", value: total, color: "var(--accent)" },
        { label: "Critical", value: critical, color: "var(--critical)" },
        { label: "Ortalama Risk", value: avgRisk, color: "var(--high)" },
        { label: "Toplam Tetiklenme", value: totalOccurrences, color: "var(--purple)" },
        { label: "MITRE Teknikleri", value: uniqueMitre.size, color: "var(--low)" },
        { label: "AI ile Analiz Edilen", value: aiAnalyzed, color: "var(--accent)" },
    ];

    document.getElementById("stats-grid").innerHTML = cards.map(c => `
        <div class="stat-card" style="--accent-color:${c.color}">
            <div class="stat-label">${c.label}</div>
            <div class="stat-value">${c.value}</div>
        </div>
    `).join("");
}

// ============ DONUT CHART (saf SVG) ============
function renderDonut() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    incidentsCache.forEach(i => { if (counts[i.severity] !== undefined) counts[i.severity]++; });
    const total = Object.values(counts).reduce((a,b)=>a+b, 0) || 1;

    const r = 42, cx = 55, cy = 55, circumference = 2 * Math.PI * r;
    let offset = 0;
    let paths = "";
    SEV_ORDER.forEach(sev => {
        const frac = counts[sev] / total;
        const dash = frac * circumference;
        paths += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${SEV_COLORS[sev]}"
            stroke-width="13" stroke-dasharray="${dash} ${circumference-dash}"
            stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cy})" stroke-linecap="butt"/>`;
        offset += dash;
    });
    document.getElementById("donut-svg").innerHTML = paths +
        `<text x="${cx}" y="${cy-3}" text-anchor="middle" fill="#eef0f5" font-size="20" font-weight="700">${total}</text>
         <text x="${cx}" y="${cy+13}" text-anchor="middle" fill="#565c70" font-size="9">incident</text>`;

    document.getElementById("donut-legend").innerHTML = SEV_ORDER.map(sev => `
        <div class="legend-row">
            <span class="legend-dot" style="background:${SEV_COLORS[sev]}"></span>
            <span style="text-transform:capitalize">${sev}</span>
            <b>${counts[sev]}</b>
        </div>
    `).join("");
}

// ============ MITRE BAR CHART ============
function renderMitreBars() {
    const counts = {};
    incidentsCache.forEach(i => {
        const list = (i.mitre && i.mitre.length ? i.mitre : (i.rule_mitre||[]));
        list.forEach(m => {
            const id = m.technique_id || m.id;
            if (!id) return;
            counts[id] = (counts[id] || 0) + 1;
        });
    });
    const sorted = Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0, 6);
    const max = sorted.length ? sorted[0][1] : 1;

    if (!sorted.length) {
        document.getElementById("mitre-bars").innerHTML = `<div class="ai-pending">Henuz MITRE verisi yok</div>`;
        return;
    }

    document.getElementById("mitre-bars").innerHTML = sorted.map(([id, count]) => `
        <div class="mitre-bar-row">
            <div class="mitre-bar-label">${id}</div>
            <div class="mitre-bar-track"><div class="mitre-bar-fill" style="width:${(count/max*100)}%"></div></div>
            <div class="mitre-bar-count">${count}</div>
        </div>
    `).join("");
}

// ============ TIMELINE (saf SVG sparkline, son 24 saat, 2 saatlik bucket) ============
function renderTimeline() {
    const now = Date.now();
    const buckets = new Array(12).fill(0); // 12 x 2 saat = 24 saat
    incidentsCache.forEach(i => {
        const t = new Date((i.first_seen||"").replace(" ", "T") + "Z").getTime();
        const diffH = (now - t) / 3600000;
        if (diffH >= 0 && diffH < 24) {
            const idx = 11 - Math.floor(diffH / 2);
            if (idx >= 0 && idx < 12) buckets[idx]++;
        }
    });
    const max = Math.max(...buckets, 1);
    const w = 300, h = 90, barW = w / 12;
    let bars = "";
    buckets.forEach((v, idx) => {
        const barH = (v / max) * (h - 20);
        const x = idx * barW + 3;
        const y = h - barH - 14;
        bars += `<rect x="${x}" y="${y}" width="${barW-6}" height="${barH}" rx="2" fill="${v>0 ? '#5b8cff' : '#1a1d28'}" opacity="${v>0 ? 0.9 : 1}"/>`;
        if (v > 0) bars += `<text x="${x+(barW-6)/2}" y="${y-4}" text-anchor="middle" fill="#8a90a4" font-size="9">${v}</text>`;
    });
    bars += `<text x="0" y="${h-2}" fill="#565c70" font-size="9">-24sa</text>`;
    bars += `<text x="${w-20}" y="${h-2}" fill="#565c70" font-size="9">simdi</text>`;
    document.getElementById("timeline-svg").innerHTML = bars;
}

// ============ FILTRE BUTONLARI ============
function renderFilters() {
    const counts = { all: incidentsCache.length };
    SEV_ORDER.forEach(s => counts[s] = incidentsCache.filter(i=>i.severity===s).length);
    const labels = { all: "Tumu", critical: "Critical", high: "High", medium: "Medium", low: "Low" };

    document.getElementById("filters-row").innerHTML = ["all", ...SEV_ORDER].map(key => `
        <button class="filter-btn ${currentFilter===key?'active':''}" data-sev="${key}">
            ${labels[key]} <span class="filter-count">${counts[key]}</span>
        </button>
    `).join("");

    document.querySelectorAll(".filter-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            currentFilter = btn.dataset.sev;
            renderFilters();
            renderIncidents();
        });
    });
}

// ============ ATTACK STORY + PROCESS TREE ============
const STORY_COLORS = {
    process: "#5b8cff", network: "#3ddc84", dns: "#a78bfa",
    registry: "#ffa53d", file: "#ffd93d", authentication: "#ff7aa2", other: "#8a90a4"
};
const STORY_ICONS = { process:"P", network:"N", dns:"D", registry:"R", file:"F", authentication:"A", other:"•" };

function storyDetail(item) {
    const bits = [];
    if (item.process) bits.push(basename(item.process));
    if (item.command_line) bits.push(item.command_line);
    if (item.dns_query) bits.push("DNS: " + item.dns_query);
    if (item.destination_ip) bits.push(item.destination_ip + (item.destination_port ? ":" + item.destination_port : ""));
    if (item.target_filename) bits.push(item.target_filename);
    if (item.registry_target) bits.push(item.registry_target);
    if (item.username && item.username !== "UNKNOWN") bits.push("user: " + item.username);
    return bits.slice(0, 2).join(" · ") || item.host || "Detay yok";
}

function renderAttackStory(story) {
    if (!story || !story.length) return `<div class="viz-empty">Bu incident icin zaman cizgisi verisi yok.</div>`;
    return `<div class="story-track">${story.slice(0, 40).map((item, idx) => {
        const cat = item.category || "other";
        const color = STORY_COLORS[cat] || STORY_COLORS.other;
        const name = item.title || item.event_type || (item.event_id ? `Event ${item.event_id}` : "Event");
        const time = item.timestamp ? new Date(String(item.timestamp).replace(" ", "T")).toLocaleTimeString("tr-TR", {hour:"2-digit",minute:"2-digit",second:"2-digit"}) : "";
        return `<div class="story-item">
            <div class="story-node" style="--story-color:${color}">${STORY_ICONS[cat] || "•"}</div>
            <div class="story-content">
                <div class="story-top"><span class="story-name">${esc(name)}</span><span class="story-cat">${esc(cat)}</span><span class="story-time">${esc(time)}</span></div>
                <div class="story-detail" title="${esc(storyDetail(item))}">${esc(storyDetail(item))}</div>
            </div>
        </div>`;
    }).join("")}</div>`;
}

function treeNodeKeyLabel(node) {
    const image = node.image || node.process || node.target_image || "Bilinmeyen process";
    const pid = node.process_id || node.target_process_id || "?";
    return { name: basename(image), meta: `PID ${pid}${node.command_line ? " · " + node.command_line : ""}` };
}

function renderTreeNode(key, nodes, seen = new Set()) {
    if (!key || seen.has(key)) return "";
    const node = nodes[key];
    if (!node) return "";
    const nextSeen = new Set(seen); nextSeen.add(key);
    const label = treeNodeKeyLabel(node);
    const children = Array.isArray(node.children) ? node.children : [];
    return `<div class="tree-wrap">
        <div class="tree-node ${node.synthetic ? "tree-synthetic" : ""}">
            <div class="tree-icon">&#9654;</div>
            <div class="tree-main"><div class="tree-name" title="${esc(label.name)}">${esc(label.name)}</div><div class="tree-meta" title="${esc(label.meta)}">${esc(label.meta)}</div></div>
        </div>
        ${children.length ? `<div class="tree-branch">${children.map(child => renderTreeNode(child, nodes, nextSeen)).join("")}</div>` : ""}
    </div>`;
}

function renderProcessTree(tree) {
    const nodes = tree?.nodes || {};
    const roots = Array.isArray(tree?.roots) ? tree.roots : [];
    if (!Object.keys(nodes).length) return `<div class="viz-empty">Bu incident icin process iliskisi yok.</div>`;
    const effectiveRoots = roots.length ? roots : Object.keys(nodes).slice(0, 10);
    return `<div class="tree-canvas"><div class="tree-root">${effectiveRoots.map(root => renderTreeNode(root, nodes)).join("")}</div></div>`;
}

function visualizationHtml(incidentId) {
    const viz = visualizationCache.get(Number(incidentId));
    if (!viz) return `<div class="visual-grid"><div class="visual-card"><div class="viz-loading">Attack Story yukleniyor...</div></div><div class="visual-card"><div class="viz-loading">Process Tree yukleniyor...</div></div></div>`;
    const story = viz.attack_story || [];
    const tree = viz.process_tree || {};
    return `<div class="visual-grid">
        <div class="visual-card">
            <div class="visual-head"><span class="visual-title">Attack Story</span><span class="visual-kpi">${story.length} adim</span></div>
            ${renderAttackStory(story)}
        </div>
        <div class="visual-card">
            <div class="visual-head"><span class="visual-title">Process Tree</span><div class="tree-stats"><span class="visual-kpi">${tree.node_count || Object.keys(tree.nodes||{}).length} node</span><span class="visual-kpi">${tree.edge_count || 0} bag</span></div></div>
            ${renderProcessTree(tree)}
        </div>
    </div>`;
}

async function ensureVisualization(incidentId) {
    const id = Number(incidentId);
    if (visualizationCache.has(id) || visualizationLoading.has(id)) return;
    visualizationLoading.add(id);
    try {
        const resp = await fetch(`/api/incidents/${id}/visualization`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        visualizationCache.set(id, await resp.json());
    } catch (e) {
        visualizationCache.set(id, {attack_story:[], process_tree:{roots:[],nodes:{},node_count:0,edge_count:0}});
    } finally {
        visualizationLoading.delete(id);
        const host = document.querySelector(`.card[data-id="${id}"] .incident-visualization`);
        if (host) host.innerHTML = visualizationHtml(id);
    }
}

function toggleIncidentCard(head) {
    const card = head.closest(".card");
    card.classList.toggle("open");
    if (card.classList.contains("open")) ensureVisualization(card.dataset.id);
}

// ============ INCIDENT KARTLARI ============
function renderCard(inc) {
    const sev = inc.severity || "low";
    const mitreList = (inc.mitre && inc.mitre.length ? inc.mitre : (inc.rule_mitre || []));
    const mitreHtml = mitreList.map(mitreLink).join(" ");

    const hasAi = !!inc.attack_name;
    const hasAiError = !!inc.ai_error;

    let aiSection = "";
    if (hasAiError) {
        aiSection = `<div class="section"><h4>AI Analizi</h4><div class="ai-error">Hata: ${esc(inc.ai_error)}</div></div>`;
    } else if (!hasAi) {
        aiSection = `<div class="section"><p class="ai-pending">Risk esigi altinda kaldigi icin AI analizi yapilmadi.</p></div>`;
    } else {
        aiSection = `
            <div class="divider"></div>
            <div class="section"><h4>&#128269; Ne oldu</h4><p>${esc(inc.what_happened || "-")}</p></div>
            <div class="section"><h4>&#9888;&#65039; Neden isaretlendi</h4><p>${esc(inc.why_flagged || "-")}</p></div>
            <div class="section"><h4>&#128203; Kanitlar</h4><ul>${(inc.evidence||[]).map(x=>`<li>${esc(x)}</li>`).join("") || "<li>-</li>"}</ul></div>
            <div class="section">
                <h4>Bilinen saldiri paterni mi ${fpBadge(inc.false_positive_likelihood)}</h4>
                <p>${inc.is_known_pattern ? "Evet, bu bilinen bir teknik." : "Belirgin bilinen bir kampanyaya net eslesme yok."}
                   ${(inc.similar_known_attacks && inc.similar_known_attacks.length) ? " Benzer: " + inc.similar_known_attacks.join(", ") : ""}</p>
            </div>
            <div class="section"><h4>&#9889; Hemen yapilmasi gerekenler</h4><ul>${(inc.immediate_actions||[]).map(x=>`<li>${esc(x)}</li>`).join("") || "<li>-</li>"}</ul></div>
            <div class="section"><h4>&#128737;&#65039; Kalici onlemler</h4><ul>${(inc.prevention_recommendations||[]).map(x=>`<li>${esc(x)}</li>`).join("") || "<li>-</li>"}</ul></div>
        `;
    }

    return `
    <div class="card" data-sev="${sev}" data-id="${inc.id}">
        <div class="card-head" onclick="toggleIncidentCard(this)">
            <span class="sev-strip" style="background:${SEV_COLORS[sev]}"></span>
            <span class="badge sev-${sev}">${sev}</span>
            <span class="attack-name">${esc(inc.attack_name || inc.incident_type)}</span>
            ${inc.occurrence_count > 1 ? `<span class="badge occ-badge">${inc.occurrence_count}&times;</span>` : ""}
            <span class="card-meta-inline">${esc(inc.host)} &middot; ${timeAgo(inc.last_seen)}</span>
            <span class="risk-pill">${inc.risk_score}</span>
            <span class="chevron">&#9656;</span>
        </div>
        <div class="card-body">
            <div class="meta-row">
                <div>Host<b>${esc(inc.host)}</b></div>
                <div>Kullanici<b>${esc(inc.username)}</b></div>
                <div>Ilk gorulme<b>${esc(inc.first_seen)}</b></div>
                <div>Son gorulme<b>${esc(inc.last_seen)}</b></div>
            </div>
            <div class="incident-visualization">${visualizationHtml(inc.id)}</div>
            ${mitreHtml ? `<div class="section"><h4>MITRE ATT&amp;CK</h4>${mitreHtml}</div>` : ""}
            ${aiSection}
        </div>
    </div>`;
}

function renderIncidents() {
    let filtered = currentFilter === "all" ? incidentsCache : incidentsCache.filter(i => i.severity === currentFilter);
    if (searchTerm) {
        const q = searchTerm.toLowerCase();
        filtered = filtered.filter(i => {
            const mitreStr = (i.mitre||i.rule_mitre||[]).map(m=>(m.technique_id||m.id||"")+(m.technique_name||m.technique||"")).join(" ");
            return (i.host||"").toLowerCase().includes(q)
                || (i.username||"").toLowerCase().includes(q)
                || (i.attack_name||"").toLowerCase().includes(q)
                || (i.incident_type||"").toLowerCase().includes(q)
                || mitreStr.toLowerCase().includes(q);
        });
    }

    const container = document.getElementById("incidents");
    if (!filtered.length) {
        container.innerHTML = `<div class="empty-state">Bu filtreye uyan incident yok.</div>`;
        return;
    }
    const openIds = new Set(Array.from(document.querySelectorAll(".card.open")).map(c => c.dataset.id));
    container.innerHTML = filtered.map(renderCard).join("");
    openIds.forEach(id => {
        const el = container.querySelector(`.card[data-id="${id}"]`);
        if (el) el.classList.add("open");
    });
}

async function fetchIncidents() {
    try {
        const resp = await fetch("/api/incidents");
        incidentsCache = await resp.json();
        document.getElementById("last-updated").textContent = "guncellendi " + new Date().toLocaleTimeString("tr-TR");
        renderStats();
        renderDonut();
        renderMitreBars();
        renderTimeline();
        renderFilters();
        renderIncidents();
    } catch (e) {
        document.getElementById("last-updated").textContent = "baglanti hatasi";
    }
}

document.getElementById("search").addEventListener("input", (e) => {
    searchTerm = e.target.value;
    renderIncidents();
});

fetchIncidents();
setInterval(fetchIncidents, 10000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("DASHBOARD_PORT", 9000))
    uvicorn.run(app, host="0.0.0.0", port=port)
