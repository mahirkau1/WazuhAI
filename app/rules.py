def detect_brute_force(events: list[dict]) -> dict | None:
    failures = [e for e in events if e["event_type"] == "authentication_failure"]
    if len(failures) >= 5:
        return {"incident_type": "possible_brute_force", "matched_events": failures, "base_risk": 45}
    return None


def detect_suspicious_powershell(events: list[dict]) -> dict | None:
    ps_events = [e for e in events if e["event_type"] == "powershell_script_block"]
    if not ps_events:
        return None
    suspicious_flags = [
        "-enc", "-encodedcommand", "downloadstring", "downloadfile",
        "invoke-expression", "iex ", "-nop", "-noprofile", "bypass",
        "hidden", "frombase64string",
    ]
    flagged = [
        e for e in ps_events
        if e.get("command_line") and any(f in e["command_line"].lower() for f in suspicious_flags)
    ]
    if flagged:
        return {"incident_type": "suspicious_powershell_execution", "matched_events": flagged, "base_risk": 55}
    return None


def detect_lsass_access(events: list[dict]) -> dict | None:
    lsass_events = []
    for e in events:
        if e["event_type"] != "sysmon_process_access":
            continue
        target = (
            e.get("raw_event", {}).get("data", {}).get("win", {})
            .get("eventdata", {}).get("targetImage", "").lower()
        )
        if "lsass" in target:
            lsass_events.append(e)
    if lsass_events:
        return {"incident_type": "possible_credential_dumping", "matched_events": lsass_events, "base_risk": 75}
    return None


def pass_through_high_severity_wazuh_rule(events: list[dict]) -> dict | None:
    """
    Wazuh'un kendisi zaten yuksek seviyeli (level >= 10) bir alarm urettiyse,
    bizim kendi kurallarimiz eslesmese bile bunu bir incident olarak isaretle --
    Wazuh'un kural motoru bizim yazdigimiz kurallardan cok daha kapsamli,
    onun "onemli" dedigine guveniyoruz.
    """
    high_sev = [e for e in events if (e.get("wazuh_rule_level") or 0) >= 10]
    if high_sev:
        return {"incident_type": "wazuh_high_severity_alert", "matched_events": high_sev, "base_risk": 65}
    return None


ALL_RULES = [
    detect_brute_force,
    detect_suspicious_powershell,
    detect_lsass_access,
    pass_through_high_severity_wazuh_rule,
]
