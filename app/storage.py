import sqlite3
import json
from contextlib import contextmanager

DB_PATH = "aegis.db"


EVENT_COLUMNS = {
    "source_port": "TEXT",
    "destination_ip": "TEXT",
    "destination_port": "TEXT",
    "protocol": "TEXT",

    "process_id": "TEXT",
    "process_guid": "TEXT",

    "parent_process_id": "TEXT",
    "parent_process_guid": "TEXT",
    "parent_image": "TEXT",
    "parent_command_line": "TEXT",

    "target_process_id": "TEXT",
    "target_process_guid": "TEXT",
    "granted_access": "TEXT",

    "target_filename": "TEXT",

    "dns_query": "TEXT",

    "registry_target": "TEXT",
    "registry_details": "TEXT",

    "hashes": "TEXT",
    "integrity_level": "TEXT",

    "user_sid": "TEXT",
    "logon_id": "TEXT",
    "logon_type": "TEXT",
}


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        yield conn
    finally:
        conn.close()


def _get_table_columns(conn, table_name: str) -> set[str]:
    """
    SQLite tablosunda mevcut kolonlari dondurur.
    """
    rows = conn.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return {row["name"] for row in rows}


def _migrate_events_table(conn):
    """
    Eski V2 aegis.db mevcutsa yeni normalize alanlarini
    tabloyu silmeden ekler.
    """

    existing_columns = _get_table_columns(conn, "events")

    for column_name, column_type in EVENT_COLUMNS.items():
        if column_name not in existing_columns:
            conn.execute(
                f"ALTER TABLE events "
                f"ADD COLUMN {column_name} {column_type}"
            )

            print(
                f"[DB MIGRATION] events.{column_name} eklendi."
            )


def init_db():
    with get_conn() as conn:

        # -----------------------------------------------------
        # EVENTS
        # -----------------------------------------------------

        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT,
                event_type TEXT,
                event_id INTEGER,

                host TEXT,
                username TEXT,

                user_sid TEXT,
                logon_id TEXT,
                logon_type TEXT,

                source_ip TEXT,
                source_port TEXT,
                destination_ip TEXT,
                destination_port TEXT,
                protocol TEXT,

                process TEXT,
                process_id TEXT,
                process_guid TEXT,
                command_line TEXT,

                parent_process_id TEXT,
                parent_process_guid TEXT,
                parent_image TEXT,
                parent_command_line TEXT,

                target_image TEXT,
                target_process_id TEXT,
                target_process_guid TEXT,
                granted_access TEXT,

                target_filename TEXT,

                dns_query TEXT,

                registry_target TEXT,
                registry_details TEXT,

                hashes TEXT,
                integrity_level TEXT,

                fingerprint TEXT,

                wazuh_rule_id TEXT,
                wazuh_rule_level INTEGER,
                wazuh_rule_description TEXT,
                wazuh_mitre TEXT,

                raw_event TEXT,

                incident_id INTEGER,

                created_at TEXT DEFAULT (datetime('now'))
            )
        """)

        # Mevcut eski DB varsa eksik kolonlari ekle.
        _migrate_events_table(conn)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_fingerprint
            ON events(fingerprint)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_incident
            ON events(incident_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_events_host_username
            ON events(host, username)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_events_timestamp
            ON events(timestamp)
        """)

        # -----------------------------------------------------
        # INCIDENTS
        # -----------------------------------------------------

        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                incident_type TEXT,
                risk_score INTEGER,
                severity TEXT,

                host TEXT,
                username TEXT,

                status TEXT DEFAULT 'NEW',
                occurrence_count INTEGER DEFAULT 1,

                rule_mitre TEXT,

                attack_name TEXT,
                verdict TEXT,
                confidence REAL,

                what_happened TEXT,
                why_flagged TEXT,

                mitre TEXT,
                evidence TEXT,

                is_known_pattern INTEGER,

                similar_known_attacks TEXT,
                immediate_actions TEXT,
                prevention_recommendations TEXT,

                false_positive_likelihood TEXT,

                ai_error TEXT,

                first_seen TEXT DEFAULT (datetime('now')),
                last_seen TEXT DEFAULT (datetime('now')),
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_incidents_type_host_user
            ON incidents(
                incident_type,
                host,
                username
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_incidents_last_seen
            ON incidents(last_seen)
        """)

        conn.commit()


def is_duplicate(fingerprint: str) -> bool:
    with get_conn() as conn:

        row = conn.execute(
            """
            SELECT 1
            FROM events
            WHERE fingerprint = ?
            LIMIT 1
            """,
            (fingerprint,)
        ).fetchone()

        return row is not None


def _serialize_json(value):
    """
    Liste/dict alanlarini SQLite icin JSON string'e cevirir.
    None ise None birakir.
    """
    if value is None:
        return None

    if isinstance(value, (dict, list)):
        return json.dumps(
            value,
            ensure_ascii=False
        )

    return str(value)


def save_event(
    e: dict,
    incident_id: int | None = None
) -> int:

    with get_conn() as conn:

        cur = conn.execute("""
            INSERT INTO events (
                timestamp,
                event_type,
                event_id,

                host,
                username,

                user_sid,
                logon_id,
                logon_type,

                source_ip,
                source_port,
                destination_ip,
                destination_port,
                protocol,

                process,
                process_id,
                process_guid,
                command_line,

                parent_process_id,
                parent_process_guid,
                parent_image,
                parent_command_line,

                target_image,
                target_process_id,
                target_process_guid,
                granted_access,

                target_filename,

                dns_query,

                registry_target,
                registry_details,

                hashes,
                integrity_level,

                fingerprint,

                wazuh_rule_id,
                wazuh_rule_level,
                wazuh_rule_description,
                wazuh_mitre,

                raw_event,

                incident_id
            )
            VALUES (
                ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?,
                ?,
                ?, ?,
                ?, ?,
                ?,
                ?, ?, ?, ?,
                ?,
                ?
            )
        """, (
            e["timestamp"],
            e["event_type"],
            e["event_id"],

            e["host"],
            e["username"],

            e.get("user_sid"),
            e.get("logon_id"),
            e.get("logon_type"),

            e.get("source_ip"),
            e.get("source_port"),
            e.get("destination_ip"),
            e.get("destination_port"),
            e.get("protocol"),

            e.get("process"),
            e.get("process_id"),
            e.get("process_guid"),
            e.get("command_line"),

            e.get("parent_process_id"),
            e.get("parent_process_guid"),
            e.get("parent_image"),
            e.get("parent_command_line"),

            e.get("target_image"),
            e.get("target_process_id"),
            e.get("target_process_guid"),
            e.get("granted_access"),

            e.get("target_filename"),

            e.get("dns_query"),

            e.get("registry_target"),
            e.get("registry_details"),

            _serialize_json(e.get("hashes")),
            e.get("integrity_level"),

            e["fingerprint"],

            e.get("wazuh_rule_id"),
            e.get("wazuh_rule_level"),
            e.get("wazuh_rule_description"),

            json.dumps(
                e.get("wazuh_mitre", []),
                ensure_ascii=False
            ),

            json.dumps(
                e.get("raw_event", {}),
                ensure_ascii=False
            ),

            incident_id,
        ))

        conn.commit()

        return cur.lastrowid


def get_related_events(
    host: str,
    username: str,
    window_minutes: int = 5
) -> list[dict]:

    with get_conn() as conn:

        rows = conn.execute("""
            SELECT *
            FROM events
            WHERE host = ?
              AND username = ?
              AND created_at >= datetime('now', ?)
            ORDER BY timestamp DESC
        """, (
            host,
            username,
            f"-{window_minutes} minutes"
        )).fetchall()

        result = []

        for r in rows:

            d = dict(r)

            if d.get("raw_event"):
                try:
                    d["raw_event"] = json.loads(
                        d["raw_event"]
                    )
                except (json.JSONDecodeError, TypeError):
                    d["raw_event"] = {}

            else:
                d["raw_event"] = {}

            if d.get("wazuh_mitre"):
                try:
                    d["wazuh_mitre"] = json.loads(
                        d["wazuh_mitre"]
                    )
                except (json.JSONDecodeError, TypeError):
                    d["wazuh_mitre"] = []

            else:
                d["wazuh_mitre"] = []

            if d.get("hashes"):
                try:
                    parsed_hashes = json.loads(
                        d["hashes"]
                    )

                    d["hashes"] = parsed_hashes

                except (
                    json.JSONDecodeError,
                    TypeError
                ):
                    pass

            result.append(d)

        return result


def get_open_incident(
    incident_type: str,
    host: str,
    username: str,
    cooldown_minutes: int = 15
) -> dict | None:

    """
    Ayni incident_type + host + username icin son cooldown
    suresi icinde acik bir incident varsa onu dondurur.
    """

    with get_conn() as conn:

        row = conn.execute("""
            SELECT *
            FROM incidents
            WHERE incident_type = ?
              AND host = ?
              AND username = ?
              AND last_seen >= datetime('now', ?)
            ORDER BY last_seen DESC
            LIMIT 1
        """, (
            incident_type,
            host,
            username,
            f"-{cooldown_minutes} minutes"
        )).fetchone()

        return dict(row) if row else None


def bump_incident_occurrence(
    incident_id: int,
    risk_score: int
):
    """
    Mevcut incident tekrar tetiklenirse:
    - occurrence_count artar
    - last_seen guncellenir
    - risk daha yuksekse yeni risk kullanilir
    - severity de yeni riskle uyumlu tutulur
    """

    severity = (
        "critical" if risk_score >= 75
        else "high" if risk_score >= 50
        else "medium" if risk_score >= 25
        else "low"
    )

    with get_conn() as conn:

        conn.execute("""
            UPDATE incidents
            SET
                occurrence_count = occurrence_count + 1,
                last_seen = datetime('now'),

                risk_score = MAX(
                    risk_score,
                    ?
                ),

                severity = CASE
                    WHEN ? > risk_score
                    THEN ?
                    ELSE severity
                END

            WHERE id = ?
        """, (
            risk_score,
            risk_score,
            severity,
            incident_id
        ))

        conn.commit()


def create_incident(
    incident_type: str,
    risk_score: int,
    host: str,
    username: str,
    rule_mitre: list[dict]
) -> int:

    severity = (
        "critical" if risk_score >= 75
        else "high" if risk_score >= 50
        else "medium" if risk_score >= 25
        else "low"
    )

    with get_conn() as conn:

        cur = conn.execute("""
            INSERT INTO incidents (
                incident_type,
                risk_score,
                severity,
                host,
                username,
                rule_mitre
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            incident_type,
            risk_score,
            severity,
            host,
            username,
            json.dumps(
                rule_mitre,
                ensure_ascii=False
            )
        ))

        conn.commit()

        return cur.lastrowid


def attach_event_to_incident(
    event_id: int,
    incident_id: int
):
    """
    Daha once kaydedilmis event'i incident'a baglar.
    """

    with get_conn() as conn:

        conn.execute("""
            UPDATE events
            SET incident_id = ?
            WHERE id = ?
        """, (
            incident_id,
            event_id
        ))

        conn.commit()


def attach_events_to_incident(
    event_ids: list[int],
    incident_id: int
):
    """
    Birden fazla eventi ayni incident'a baglar.
    """

    if not event_ids:
        return

    with get_conn() as conn:

        conn.executemany("""
            UPDATE events
            SET incident_id = ?
            WHERE id = ?
        """, [
            (
                incident_id,
                event_id
            )
            for event_id in event_ids
        ])

        conn.commit()


def save_ai_result(
    incident_id: int,
    ai_result: dict
):

    with get_conn() as conn:

        conn.execute("""
            UPDATE incidents
            SET
                attack_name = ?,
                verdict = ?,
                confidence = ?,

                what_happened = ?,
                why_flagged = ?,

                mitre = ?,
                evidence = ?,

                is_known_pattern = ?,

                similar_known_attacks = ?,
                immediate_actions = ?,
                prevention_recommendations = ?,

                false_positive_likelihood = ?,

                ai_error = NULL

            WHERE id = ?
        """, (
            ai_result.get("attack_name"),
            ai_result.get("verdict"),
            ai_result.get("confidence"),

            ai_result.get("what_happened"),
            ai_result.get("why_flagged"),

            json.dumps(
                ai_result.get("mitre", []),
                ensure_ascii=False
            ),

            json.dumps(
                ai_result.get("evidence", []),
                ensure_ascii=False
            ),

            int(
                ai_result.get(
                    "is_known_pattern",
                    False
                )
            ),

            json.dumps(
                ai_result.get(
                    "similar_known_attacks",
                    []
                ),
                ensure_ascii=False
            ),

            json.dumps(
                ai_result.get(
                    "immediate_actions",
                    []
                ),
                ensure_ascii=False
            ),

            json.dumps(
                ai_result.get(
                    "prevention_recommendations",
                    []
                ),
                ensure_ascii=False
            ),

            ai_result.get(
                "false_positive_likelihood"
            ),

            incident_id,
        ))

        conn.commit()


def save_ai_error(
    incident_id: int,
    error_message: str
):

    with get_conn() as conn:

        conn.execute("""
            UPDATE incidents
            SET ai_error = ?
            WHERE id = ?
        """, (
            error_message,
            incident_id
        ))

        conn.commit()


def list_incidents(
    limit: int = 50
) -> list[dict]:

    with get_conn() as conn:

        rows = conn.execute("""
            SELECT *
            FROM incidents
            ORDER BY last_seen DESC
            LIMIT ?
        """, (
            limit,
        )).fetchall()

        result = []

        json_fields = [
            "similar_known_attacks",
            "immediate_actions",
            "prevention_recommendations",
            "mitre",
            "evidence",
            "rule_mitre",
        ]

        for r in rows:

            d = dict(r)

            for field in json_fields:

                if d.get(field):
                    try:
                        d[field] = json.loads(
                            d[field]
                        )

                    except (
                        json.JSONDecodeError,
                        TypeError
                    ):
                        d[field] = []

                else:
                    d[field] = []

            result.append(d)

        return result


def get_incident_events(
    incident_id: int
) -> list[dict]:

    with get_conn() as conn:

        rows = conn.execute("""
            SELECT *
            FROM events
            WHERE incident_id = ?
            ORDER BY timestamp ASC
        """, (
            incident_id,
        )).fetchall()

        result = []

        for row in rows:

            d = dict(row)

            if d.get("raw_event"):
                try:
                    d["raw_event"] = json.loads(
                        d["raw_event"]
                    )
                except (
                    json.JSONDecodeError,
                    TypeError
                ):
                    d["raw_event"] = {}

            if d.get("wazuh_mitre"):
                try:
                    d["wazuh_mitre"] = json.loads(
                        d["wazuh_mitre"]
                    )
                except (
                    json.JSONDecodeError,
                    TypeError
                ):
                    d["wazuh_mitre"] = []

            if d.get("hashes"):
                try:
                    d["hashes"] = json.loads(
                        d["hashes"]
                    )
                except (
                    json.JSONDecodeError,
                    TypeError
                ):
                    pass

            result.append(d)

        return result


# ============================================================
# ATTACK STORY / PROCESS TREE
# ============================================================

def _event_display_name(event: dict) -> str:
    if event.get("process"):
        return str(event["process"])
    if event.get("target_filename"):
        return str(event["target_filename"])
    if event.get("dns_query"):
        return str(event["dns_query"])
    if event.get("registry_target"):
        return str(event["registry_target"])
    if event.get("destination_ip"):
        destination = str(event["destination_ip"])
        if event.get("destination_port"):
            destination += f":{event['destination_port']}"
        return destination
    return str(event.get("event_type") or "event")


def _classify_story_event(event: dict) -> str:
    event_type = str(event.get("event_type") or "").lower()
    if event.get("dns_query"):
        return "dns"
    if event.get("destination_ip") or event.get("destination_port") or "network" in event_type or "connection" in event_type:
        return "network"
    if event.get("registry_target"):
        return "registry"
    if event.get("target_filename"):
        return "file"
    if event.get("process") or event.get("process_guid") or "process" in event_type:
        return "process"
    if event.get("logon_id") or event.get("logon_type") or "logon" in event_type or "login" in event_type:
        return "authentication"
    return "other"


def build_attack_story(events: list[dict]) -> list[dict]:
    story = []
    detail_fields = [
        "process", "process_id", "process_guid", "command_line",
        "parent_process_id", "parent_process_guid", "parent_image",
        "parent_command_line", "target_image", "target_process_id",
        "target_process_guid", "granted_access", "source_ip", "source_port",
        "destination_ip", "destination_port", "protocol", "target_filename",
        "dns_query", "registry_target", "registry_details", "hashes",
        "integrity_level", "user_sid", "logon_id", "logon_type",
    ]

    for event in events:
        details = {}
        for field in detail_fields:
            value = event.get(field)
            if value not in (None, "", [], {}):
                details[field] = value

        story.append({
            "event_db_id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "category": _classify_story_event(event),
            "event_type": event.get("event_type"),
            "event_id": event.get("event_id"),
            "title": _event_display_name(event),
            "host": event.get("host"),
            "username": event.get("username"),
            "wazuh_rule_level": event.get("wazuh_rule_level"),
            "wazuh_rule_description": event.get("wazuh_rule_description"),
            "details": details,
        })

    story.sort(key=lambda item: (
        str(item.get("timestamp") or ""),
        int(item.get("event_db_id") or 0),
    ))

    for index, item in enumerate(story, start=1):
        item["step"] = index

    return story


def _process_node_key(event: dict) -> str | None:
    if event.get("process_guid"):
        return f"guid:{event['process_guid']}"
    if event.get("process_id"):
        return f"pid:{event.get('host') or ''}:{event['process_id']}"
    return None


def _parent_node_key(event: dict) -> str | None:
    if event.get("parent_process_guid"):
        return f"guid:{event['parent_process_guid']}"
    if event.get("parent_process_id"):
        return f"pid:{event.get('host') or ''}:{event['parent_process_id']}"
    return None


def build_process_tree(events: list[dict]) -> dict:
    nodes = {}
    child_to_parent = {}

    for event in events:
        node_key = _process_node_key(event)
        if not node_key:
            continue

        if node_key not in nodes:
            nodes[node_key] = {
                "id": node_key,
                "process_guid": event.get("process_guid"),
                "process_id": event.get("process_id"),
                "image": event.get("process"),
                "command_line": event.get("command_line"),
                "host": event.get("host"),
                "username": event.get("username"),
                "integrity_level": event.get("integrity_level"),
                "first_seen": event.get("timestamp"),
                "last_seen": event.get("timestamp"),
                "event_ids": [],
                "children": [],
                "synthetic": False,
                "target_only": False,
            }

        node = nodes[node_key]
        if event.get("process") and not node.get("image"):
            node["image"] = event.get("process")
        if event.get("command_line") and not node.get("command_line"):
            node["command_line"] = event.get("command_line")
        if event.get("integrity_level") and not node.get("integrity_level"):
            node["integrity_level"] = event.get("integrity_level")

        timestamp = event.get("timestamp")
        if timestamp:
            if not node.get("first_seen") or timestamp < node["first_seen"]:
                node["first_seen"] = timestamp
            if not node.get("last_seen") or timestamp > node["last_seen"]:
                node["last_seen"] = timestamp

        if event.get("id") is not None and event["id"] not in node["event_ids"]:
            node["event_ids"].append(event["id"])

        parent_key = _parent_node_key(event)
        if parent_key and parent_key != node_key:
            child_to_parent[node_key] = parent_key
            if parent_key not in nodes:
                nodes[parent_key] = {
                    "id": parent_key,
                    "process_guid": event.get("parent_process_guid"),
                    "process_id": event.get("parent_process_id"),
                    "image": event.get("parent_image"),
                    "command_line": event.get("parent_command_line"),
                    "host": event.get("host"),
                    "username": event.get("username"),
                    "integrity_level": None,
                    "first_seen": None,
                    "last_seen": None,
                    "event_ids": [],
                    "children": [],
                    "synthetic": True,
                    "target_only": False,
                }

    for event in events:
        target_guid = event.get("target_process_guid")
        target_pid = event.get("target_process_id")
        if target_guid:
            target_key = f"guid:{target_guid}"
        elif target_pid:
            target_key = f"pid:{event.get('host') or ''}:{target_pid}"
        else:
            continue

        if target_key not in nodes:
            nodes[target_key] = {
                "id": target_key,
                "process_guid": target_guid,
                "process_id": target_pid,
                "image": event.get("target_image"),
                "command_line": None,
                "host": event.get("host"),
                "username": event.get("username"),
                "integrity_level": None,
                "first_seen": event.get("timestamp"),
                "last_seen": event.get("timestamp"),
                "event_ids": [event["id"]] if event.get("id") is not None else [],
                "children": [],
                "synthetic": True,
                "target_only": True,
            }

    for child_key, parent_key in child_to_parent.items():
        child = nodes.get(child_key)
        parent = nodes.get(parent_key)
        if child and parent and child_key not in parent["children"]:
            parent["children"].append(child_key)

    roots = [key for key in nodes if key not in child_to_parent]
    roots.sort()
    for node in nodes.values():
        node["children"].sort()

    return {
        "roots": roots,
        "nodes": nodes,
        "node_count": len(nodes),
        "edge_count": sum(len(node["children"]) for node in nodes.values()),
    }


def get_incident_attack_story(incident_id: int) -> list[dict]:
    return build_attack_story(get_incident_events(incident_id))


def get_incident_process_tree(incident_id: int) -> dict:
    return build_process_tree(get_incident_events(incident_id))


def get_incident_visualization(incident_id: int) -> dict:
    events = get_incident_events(incident_id)
    return {
        "incident_id": incident_id,
        "attack_story": build_attack_story(events),
        "process_tree": build_process_tree(events),
    }

