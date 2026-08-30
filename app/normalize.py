import hashlib
from datetime import datetime, timezone


EVENT_TYPE_MAP = {
    4624: "authentication_success",
    4625: "authentication_failure",
    4688: "process_creation",

    # Sysmon
    1: "sysmon_process_creation",
    3: "sysmon_network_connection",
    10: "sysmon_process_access",
    11: "sysmon_file_create",
    12: "sysmon_registry_event",
    13: "sysmon_registry_event",
    22: "sysmon_dns_query",

    # PowerShell
    4104: "powershell_script_block",
}


def _extract_mitre(rule: dict) -> list[dict]:
    """
    Wazuh'un rule.mitre alani surumden surume farkli sekillerde gelebilir.

    Beklenen cikti:
    [
        {
            "id": "T1082",
            "tactic": "Discovery",
            "technique": "System Information Discovery"
        }
    ]
    """
    mitre_raw = rule.get("mitre", {})

    if not mitre_raw:
        return []

    # Beklenmeyen format gelirse normalize islemini patlatma.
    if not isinstance(mitre_raw, dict):
        return []

    ids = mitre_raw.get("id", [])
    tactics = mitre_raw.get("tactic", [])
    techniques = mitre_raw.get("technique", [])

    if isinstance(ids, str):
        ids = [ids]

    if isinstance(tactics, str):
        tactics = [tactics]

    if isinstance(techniques, str):
        techniques = [techniques]

    if not isinstance(ids, list):
        ids = []

    if not isinstance(tactics, list):
        tactics = []

    if not isinstance(techniques, list):
        techniques = []

    result = []

    for i, tid in enumerate(ids):
        if not tid:
            continue

        result.append({
            "id": str(tid),
            "tactic": (
                tactics[i]
                if i < len(tactics)
                else (tactics[0] if tactics else "")
            ),
            "technique": (
                techniques[i]
                if i < len(techniques)
                else (techniques[0] if techniques else "")
            ),
        })

    return result


def _safe_event_id(value) -> int | None:
    """
    Wazuh/Sysmon event ID degerini guvenli sekilde integer'a cevirir.
    """
    if value is None:
        return None

    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _build_fingerprint(normalized: dict) -> str:
    """
    Event tipine gore daha ayirt edici fingerprint olusturur.

    Eski sistem:
        dakika + event_type + username + host + source_ip

    Bu fazla kaba oldugu icin ayni dakika icindeki farkli olaylar
    duplicate olarak algilanabiliyordu.

    Yeni sistem event turune gore farkli alanlar kullanir.
    """

    event_type = normalized.get("event_type", "")
    timestamp = normalized.get("timestamp", "")
    host = normalized.get("host", "UNKNOWN")
    username = normalized.get("username", "UNKNOWN")

    # ---------------------------------------------------------
    # PROCESS CREATION
    # ---------------------------------------------------------
    if event_type in (
        "process_creation",
        "sysmon_process_creation",
        "powershell_script_block",
    ):
        parts = [
            timestamp,
            event_type,
            host,
            username,
            normalized.get("process_guid"),
            normalized.get("process_id"),
            normalized.get("process"),
            normalized.get("command_line"),
            normalized.get("parent_process_guid"),
            normalized.get("parent_image"),
        ]

    # ---------------------------------------------------------
    # NETWORK CONNECTION
    # ---------------------------------------------------------
    elif event_type == "sysmon_network_connection":
        parts = [
            timestamp,
            event_type,
            host,
            username,
            normalized.get("process_guid"),
            normalized.get("process"),
            normalized.get("source_ip"),
            normalized.get("source_port"),
            normalized.get("destination_ip"),
            normalized.get("destination_port"),
            normalized.get("protocol"),
        ]

    # ---------------------------------------------------------
    # AUTHENTICATION
    # ---------------------------------------------------------
    elif event_type in (
        "authentication_success",
        "authentication_failure",
    ):
        parts = [
            timestamp,
            event_type,
            host,
            username,
            normalized.get("source_ip"),
            normalized.get("logon_type"),
            normalized.get("logon_id"),
        ]

    # ---------------------------------------------------------
    # FILE CREATION
    # ---------------------------------------------------------
    elif event_type == "sysmon_file_create":
        parts = [
            timestamp,
            event_type,
            host,
            username,
            normalized.get("process_guid"),
            normalized.get("process"),
            normalized.get("target_filename"),
        ]

    # ---------------------------------------------------------
    # REGISTRY
    # ---------------------------------------------------------
    elif event_type == "sysmon_registry_event":
        parts = [
            timestamp,
            event_type,
            host,
            username,
            normalized.get("process_guid"),
            normalized.get("process"),
            normalized.get("registry_target"),
            normalized.get("registry_details"),
        ]

    # ---------------------------------------------------------
    # DNS
    # ---------------------------------------------------------
    elif event_type == "sysmon_dns_query":
        parts = [
            timestamp,
            event_type,
            host,
            username,
            normalized.get("process_guid"),
            normalized.get("process"),
            normalized.get("dns_query"),
        ]

    # ---------------------------------------------------------
    # PROCESS ACCESS
    # ---------------------------------------------------------
    elif event_type == "sysmon_process_access":
        parts = [
            timestamp,
            event_type,
            host,
            username,
            normalized.get("process_guid"),
            normalized.get("process"),
            normalized.get("target_image"),
            normalized.get("target_process_guid"),
            normalized.get("granted_access"),
        ]

    # ---------------------------------------------------------
    # DIGER EVENTLER
    # ---------------------------------------------------------
    else:
        parts = [
            timestamp,
            event_type,
            host,
            username,
            normalized.get("source_ip"),
            normalized.get("process"),
            normalized.get("command_line"),
            normalized.get("target_filename"),
            normalized.get("wazuh_rule_id"),
        ]

    # None degerlerini guvenli sekilde string'e cevir.
    fp_source = "|".join(
        "" if value is None else str(value)
        for value in parts
    )

    return hashlib.sha256(
        fp_source.encode("utf-8")
    ).hexdigest()


def normalize_alert(raw: dict) -> dict | None:
    """
    Ham Wazuh alert'ini AegisAI'nin kullanacagi ortak event formatina cevirir.
    """

    if not isinstance(raw, dict):
        return None

    win = raw.get("data", {}).get("win", {})

    if not isinstance(win, dict):
        return None

    system = win.get("system", {}) or {}
    event_data = win.get("eventdata", {}) or {}

    if not isinstance(system, dict):
        system = {}

    if not isinstance(event_data, dict):
        event_data = {}

    # ---------------------------------------------------------
    # EVENT ID
    # ---------------------------------------------------------

    event_id = _safe_event_id(system.get("eventID"))

    if event_id is None:
        return None

    # ---------------------------------------------------------
    # TEMEL BILGILER
    # ---------------------------------------------------------

    agent = raw.get("agent", {}) or {}

    host = (
        agent.get("name")
        if isinstance(agent, dict)
        else None
    ) or "UNKNOWN"

    username = (
        event_data.get("targetUserName")
        or event_data.get("subjectUserName")
        or event_data.get("sourceUser")
        or event_data.get("targetUser")
        or event_data.get("user")
        or "UNKNOWN"
    )

    source_ip = (
        event_data.get("sourceIp")
        or event_data.get("ipAddress")
        or event_data.get("sourceAddress")
        or "UNKNOWN"
    )

    timestamp = (
        raw.get("timestamp")
        or datetime.now(timezone.utc).isoformat()
    )

    rule = raw.get("rule", {}) or {}

    if not isinstance(rule, dict):
        rule = {}

    # ---------------------------------------------------------
    # NORMALIZED EVENT
    # ---------------------------------------------------------

    normalized = {
        # Temel event bilgileri
        "event_type": EVENT_TYPE_MAP.get(
            event_id,
            f"unknown_event_{event_id}"
        ),
        "event_id": event_id,
        "timestamp": timestamp,

        # Host / identity
        "host": host,
        "username": username,
        "user_sid": (
            event_data.get("userId")
            or event_data.get("targetUserSid")
            or event_data.get("subjectUserSid")
        ),
        "logon_id": (
            event_data.get("targetLogonId")
            or event_data.get("subjectLogonId")
        ),
        "logon_type": event_data.get("logonType"),

        # Network
        "source_ip": source_ip,
        "source_port": event_data.get("sourcePort"),
        "destination_ip": event_data.get("destinationIp"),
        "destination_port": event_data.get("destinationPort"),
        "protocol": event_data.get("protocol"),

        # Process
        "process": (
            event_data.get("sourceImage")
            or event_data.get("image")
            or event_data.get("newProcessName")
        ),
        "process_id": (
            event_data.get("sourceProcessId")
            or event_data.get("processId")
            or event_data.get("newProcessId")
        ),
        "process_guid": (
            event_data.get("sourceProcessGUID")
            or event_data.get("sourceProcessGuid")
            or event_data.get("processGUID")
            or event_data.get("processGuid")
        ),

        "command_line": (
            event_data.get("scriptBlockText")
            or event_data.get("commandLine")
        ),

        # Parent process
        "parent_process_id": event_data.get("parentProcessId"),
        "parent_process_guid": (
            event_data.get("parentProcessGUID")
            or event_data.get("parentProcessGuid")
        ),
        "parent_image": event_data.get("parentImage"),
        "parent_command_line": event_data.get("parentCommandLine"),

        # Process access
        "target_image": event_data.get("targetImage"),
        "target_process_id": event_data.get("targetProcessId"),
        "target_process_guid": (
            event_data.get("targetProcessGUID")
            or event_data.get("targetProcessGuid")
        ),
        "granted_access": event_data.get("grantedAccess"),

        # File
        "target_filename": event_data.get("targetFilename"),

        # DNS
        "dns_query": (
            event_data.get("queryName")
            or event_data.get("query")
        ),

        # Registry
        "registry_target": event_data.get("targetObject"),
        "registry_details": event_data.get("details"),

        # File/process hashes
        "hashes": event_data.get("hashes"),

        # Process integrity
        "integrity_level": event_data.get("integrityLevel"),

        # Wazuh
        "wazuh_rule_id": rule.get("id"),
        "wazuh_rule_level": rule.get("level"),
        "wazuh_rule_description": rule.get("description"),
        "wazuh_rule_groups": rule.get("groups", []),
        "wazuh_mitre": _extract_mitre(rule),

        # Ham event'i de koruyoruz.
        "raw_event": raw,
    }

    # ---------------------------------------------------------
    # EVENT FINGERPRINT
    # ---------------------------------------------------------

    normalized["fingerprint"] = _build_fingerprint(normalized)

    return normalized
