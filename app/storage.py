import sqlite3
import json
from contextlib import contextmanager

DB_PATH = "aegis.db"


def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                event_id INTEGER,
                host TEXT,
                username TEXT,
                source_ip TEXT,
                process TEXT,
                command_line TEXT,
                fingerprint TEXT,
                wazuh_rule_id TEXT,
                wazuh_rule_level INTEGER,
                wazuh_rule_description TEXT,
                raw_event TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint ON events(fingerprint)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_type TEXT,
                risk_score INTEGER,
                severity TEXT,
                host TEXT,
                username TEXT,
                status TEXT DEFAULT 'NEW',
                attack_name TEXT,
                verdict TEXT,
                confidence REAL,
                summary TEXT,
                is_known_pattern INTEGER,
                similar_known_attacks TEXT,
                remediation_steps TEXT,
                prevention_recommendations TEXT,
                mitre TEXT,
                evidence TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def is_duplicate(fingerprint: str) -> bool:
    with get_conn() as conn:
        row = conn.execute("SELECT 1 FROM events WHERE fingerprint = ?", (fingerprint,)).fetchone()
        return row is not None


def save_event(e: dict) -> int:
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO events (timestamp, event_type, event_id, host, username,
                source_ip, process, command_line, fingerprint,
                wazuh_rule_id, wazuh_rule_level, wazuh_rule_description, raw_event)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            e["timestamp"], e["event_type"], e["event_id"], e["host"], e["username"],
            e["source_ip"], e.get("process"), e.get("command_line"), e["fingerprint"],
            e.get("wazuh_rule_id"), e.get("wazuh_rule_level"), e.get("wazuh_rule_description"),
            json.dumps(e["raw_event"]),
        ))
        conn.commit()
        return cur.lastrowid


def get_related_events(host: str, username: str, window_minutes: int = 5) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM events
            WHERE host = ? AND username = ?
              AND created_at >= datetime('now', ?)
            ORDER BY timestamp DESC
        """, (host, username, f"-{window_minutes} minutes")).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["raw_event"] = json.loads(d["raw_event"]) if d["raw_event"] else {}
            result.append(d)
        return result


def create_incident(incident_type: str, risk_score: int, host: str, username: str) -> int:
    severity = (
        "critical" if risk_score >= 75 else
        "high" if risk_score >= 50 else
        "medium" if risk_score >= 25 else
        "low"
    )
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO incidents (incident_type, risk_score, severity, host, username)
            VALUES (?, ?, ?, ?, ?)
        """, (incident_type, risk_score, severity, host, username))
        conn.commit()
        return cur.lastrowid


def save_ai_result(incident_id: int, ai_result: dict):
    with get_conn() as conn:
        conn.execute("""
            UPDATE incidents SET
                attack_name = ?, verdict = ?, confidence = ?, summary = ?,
                is_known_pattern = ?, similar_known_attacks = ?,
                remediation_steps = ?, prevention_recommendations = ?,
                mitre = ?, evidence = ?
            WHERE id = ?
        """, (
            ai_result.get("attack_name"), ai_result.get("verdict"), ai_result.get("confidence"),
            ai_result.get("summary"), int(ai_result.get("is_known_pattern", False)),
            json.dumps(ai_result.get("similar_known_attacks", [])),
            json.dumps(ai_result.get("remediation_steps", [])),
            json.dumps(ai_result.get("prevention_recommendations", [])),
            json.dumps(ai_result.get("mitre", [])),
            json.dumps(ai_result.get("evidence", [])),
            incident_id,
        ))
        conn.commit()


def list_incidents(limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for field in ["similar_known_attacks", "remediation_steps", "prevention_recommendations", "mitre", "evidence"]:
                if d.get(field):
                    d[field] = json.loads(d[field])
            result.append(d)
        return result
