import hashlib
from datetime import datetime

EVENT_TYPE_MAP = {
    4624: "authentication_success",
    4625: "authentication_failure",
    4688: "process_creation",
    1: "sysmon_process_creation",
    3: "sysmon_network_connection",
    10: "sysmon_process_access",
    11: "sysmon_file_create",
    12: "sysmon_registry_event",
    13: "sysmon_registry_event",
    22: "sysmon_dns_query",
    4104: "powershell_script_block",
}


def normalize_alert(raw: dict) -> dict | None:
    win = raw.get("data", {}).get("win", {})
    system = win.get("system", {})
    event_data = win.get("eventdata", {})

    event_id_raw = system.get("eventID")
    if event_id_raw is None:
        return None

    try:
        event_id = int(event_id_raw)
    except ValueError:
        return None

    host = raw.get("agent", {}).get("name", "UNKNOWN")
    username = (
        event_data.get("targetUserName")
        or event_data.get("subjectUserName")
        or event_data.get("user")
        or "UNKNOWN"
    )
    source_ip = event_data.get("sourceIp") or event_data.get("ipAddress", "UNKNOWN")
    timestamp = raw.get("timestamp") or datetime.utcnow().isoformat()
    rule = raw.get("rule", {})

    normalized = {
        "event_type": EVENT_TYPE_MAP.get(event_id, f"unknown_event_{event_id}"),
        "event_id": event_id,
        "host": host,
        "username": username,
        "source_ip": source_ip,
        "process": event_data.get("image"),
        "command_line": event_data.get("scriptBlockText") or event_data.get("commandLine"),
        "timestamp": timestamp,
        "wazuh_rule_id": rule.get("id"),
        "wazuh_rule_level": rule.get("level"),
        "wazuh_rule_description": rule.get("description"),
        "wazuh_mitre": rule.get("mitre", {}),
        "raw_event": raw,
    }

    time_bucket = timestamp[:16]
    fp_source = f"{time_bucket}|{normalized['event_type']}|{username}|{host}|{source_ip}"
    normalized["fingerprint"] = hashlib.sha256(fp_source.encode()).hexdigest()

    return normalized
