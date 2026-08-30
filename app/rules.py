"""
AegisAI Korelasyon Kurallari -- MITRE ATT&CK taktiklerine gore organize edildi.

Her kural fonksiyonu ilgili event tipini/paternini arar; eslesme bulursa
bir "incident draft" doner:
    incident_type, matched_events, base_risk, mitre

Bu surum normalize.py/storage.py tarafinda eklenen yeni alanlari dogrudan
kullanir; gerekirse raw Wazuh event'ine fallback yapar.

base_risk seviyeleri:
  10-20  -> dusuk sinyal / bilgilendirme
  35-50  -> orta seviye
  55-70  -> yuksek
  75+    -> kritik

Not:
- Kurallar deterministik detection katmanidir.
- Tek bir kural kesin saldiri karari vermek zorunda degildir.
- Agent tarafinda birden fazla kural birlikte degerlendirilebilir.
"""

# ============================================================
# YARDIMCI FONKSIYONLAR
# ============================================================


def _collect_mitre(events: list[dict]) -> list[dict]:
    """Eslesen event'lerdeki MITRE etiketlerini ID bazinda tekillestir."""
    seen = set()
    result = []

    for e in events:
        for m in e.get("wazuh_mitre", []) or []:
            if not isinstance(m, dict):
                continue

            key = m.get("id")

            if key and key not in seen:
                seen.add(key)
                result.append(m)

    return result


def _cmdline_contains_any(events: list[dict], flags: list[str]) -> list[dict]:
    """Command line icinde verilen ifadelerden en az birini iceren event'leri doner."""
    lowered_flags = [f.lower() for f in flags]

    result = []

    for e in events:
        cmd = (e.get("command_line") or "").lower()

        if cmd and any(flag in cmd for flag in lowered_flags):
            result.append(e)

    return result


def _get_eventdata_field(e: dict, field: str) -> str:
    """Ham Wazuh event'inden win.eventdata alanini guvenli sekilde cek."""
    raw = e.get("raw_event") or {}

    if not isinstance(raw, dict):
        return ""

    return (
        raw.get("data", {})
        .get("win", {})
        .get("eventdata", {})
        .get(field, "")
        or ""
    )


def _normalized_or_raw(e: dict, normalized_field: str, raw_field: str):
    """
    Once normalize edilmis alani kullan.
    Yoksa geriye donuk uyumluluk icin raw eventdata alanina bak.
    """
    value = e.get(normalized_field)

    if value not in (None, ""):
        return value

    return _get_eventdata_field(e, raw_field)


def _process_name(value: str | None) -> str:
    """Tam path verilse bile sadece karsilastirma icin kucuk harfe cevir."""
    return (value or "").strip().lower()


def _unique_events(events: list[dict]) -> list[dict]:
    """Ayni DB event'i/fingerprint'i bir kural sonucunda iki kez tasimayi engelle."""
    seen = set()
    result = []

    for e in events:
        key = e.get("id") or e.get("fingerprint") or id(e)

        if key in seen:
            continue

        seen.add(key)
        result.append(e)

    return result


COMMON_PORTS = {
    53, 80, 123, 137, 138, 139, 443, 445, 3389, 5353
}


# ============================================================
# KATEGORI: CREDENTIAL ACCESS
# ============================================================


def detect_brute_force(events: list[dict]) -> dict | None:
    """5+ basarisiz login denemesi."""
    failures = [
        e for e in events
        if e.get("event_type") == "authentication_failure"
    ]

    if len(failures) < 5:
        return None

    return {
        "incident_type": "possible_brute_force",
        "matched_events": failures,
        "base_risk": 45,
        "mitre": _collect_mitre(failures) or [
            {
                "id": "T1110",
                "tactic": "Credential Access",
                "technique": "Brute Force",
            }
        ],
    }


def detect_lsass_access(events: list[dict]) -> dict | None:
    """
    LSASS'a process access.

    Not: LSASS erisimi tek basina her zaman credential dumping degildir.
    EDR/AV ve yonetim yazilimlari da erisebilir. Bu nedenle kural
    'possible_credential_dumping' olarak kalir.
    """
    hits = []

    for e in events:
        if e.get("event_type") != "sysmon_process_access":
            continue

        target = _process_name(e.get("target_image"))

        if target.endswith("\\lsass.exe") or target.endswith("/lsass.exe") or target == "lsass.exe":
            hits.append(e)

    if not hits:
        return None

    return {
        "incident_type": "possible_credential_dumping",
        "matched_events": hits,
        "base_risk": 75,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1003.001",
                "tactic": "Credential Access",
                "technique": "LSASS Memory",
            }
        ],
    }


def detect_credential_file_access(events: list[dict]) -> dict | None:
    """Credential icerebilecek tipik dosya/hive olusumlarini tespit eder."""
    suspicious_names = [
        "unattend.xml",
        "sysprep.inf",
        "web.config",
        ".kdbx",
        "id_rsa",
        "sam.hiv",
        "system.hiv",
        "ntds.dit",
        "credentials.xml",
        ".pfx",
    ]

    hits = []

    for e in events:
        if e.get("event_type") != "sysmon_file_create":
            continue

        filename = (e.get("target_filename") or "").lower()

        if any(name in filename for name in suspicious_names):
            hits.append(e)

    if not hits:
        return None

    return {
        "incident_type": "credential_file_access",
        "matched_events": hits,
        "base_risk": 60,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1552.001",
                "tactic": "Credential Access",
                "technique": "Credentials In Files",
            }
        ],
    }


# ============================================================
# KATEGORI: EXECUTION
# ============================================================


def detect_suspicious_process_chain(events: list[dict]) -> dict | None:
    """
    Office uygulamalarinin shell/script motoru baslatmasi gibi
    supheli parent-child process zincirlerini tespit eder.
    """
    suspicious_parent_child = {
        "winword.exe": {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        },
        "excel.exe": {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        },
        "powerpnt.exe": {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        },
        "outlook.exe": {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        },
    }

    hits = []

    for e in events:
        if e.get("event_type") not in (
            "process_creation",
            "sysmon_process_creation",
        ):
            continue

        parent = _process_name(e.get("parent_image"))
        child = _process_name(e.get("process"))

        if not parent or not child:
            continue

        for parent_name, child_names in suspicious_parent_child.items():
            if not parent.endswith(parent_name):
                continue

            if any(child.endswith(child_name) for child_name in child_names):
                hits.append(e)
                break

    hits = _unique_events(hits)

    if not hits:
        return None

    return {
        "incident_type": "suspicious_process_chain",
        "matched_events": hits,
        "base_risk": 65,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1204",
                "tactic": "Execution",
                "technique": "User Execution",
            },
            {
                "id": "T1059",
                "tactic": "Execution",
                "technique": "Command and Scripting Interpreter",
            },
        ],
    }


def detect_suspicious_powershell(events: list[dict]) -> dict | None:
    """
    Obfuscation, indirme, gizleme veya policy bypass belirtileri tasiyan
    PowerShell komutlarini puanlayarak tespit eder.

    Tek basina -NoProfile gibi yaygin bir parametre alarm icin yeterli degildir.
    """
    ps_events = [
        e for e in events
        if e.get("event_type") == "powershell_script_block"
        or _process_name(e.get("process")).endswith("powershell.exe")
        or _process_name(e.get("process")).endswith("pwsh.exe")
    ]

    if not ps_events:
        return None

    weighted_flags = {
        "-encodedcommand": 4,
        "-enc ": 4,
        "frombase64string": 3,
        "invoke-expression": 3,
        "iex ": 3,
        "downloadstring": 4,
        "downloadfile": 4,
        "invoke-webrequest": 3,
        "net.webclient": 3,
        "http://": 2,
        "https://": 2,
        "bypass": 2,
        "-windowstyle hidden": 2,
        " hidden": 1,
        "-nop": 1,
        "-noprofile": 1,
    }

    hits = []

    for e in ps_events:
        cmd = (e.get("command_line") or "").lower()

        if not cmd:
            continue

        score = sum(
            weight
            for flag, weight in weighted_flags.items()
            if flag in cmd
        )

        if score >= 5:
            hits.append(e)

    hits = _unique_events(hits)

    if not hits:
        return None

    return {
        "incident_type": "suspicious_powershell_execution",
        "matched_events": hits,
        "base_risk": 55,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1059.001",
                "tactic": "Execution",
                "technique": "PowerShell",
            }
        ],
    }


def detect_living_off_the_land(events: list[dict]) -> dict | None:
    """Yaygin LOLBin'lerin supheli argumanlarla kullanilmasini tespit eder."""
    lolbins = [
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "wmic.exe",
        "cscript.exe",
        "wscript.exe",
    ]

    suspicious_args = [
        "http://",
        "https://",
        "-urlcache",
        "-decode",
        "javascript:",
        "vbscript:",
    ]

    hits = []

    for e in events:
        process = _process_name(e.get("process"))
        cmd = (e.get("command_line") or "").lower()

        if not process or not cmd:
            continue

        if any(process.endswith(lb) for lb in lolbins) and any(
            arg in cmd for arg in suspicious_args
        ):
            hits.append(e)

    hits = _unique_events(hits)

    if not hits:
        return None

    return {
        "incident_type": "living_off_the_land_binary_abuse",
        "matched_events": hits,
        "base_risk": 60,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1218",
                "tactic": "Defense Evasion",
                "technique": "System Binary Proxy Execution",
            }
        ],
    }


# ============================================================
# KATEGORI: PERSISTENCE
# ============================================================


def detect_registry_persistence(events: list[dict]) -> dict | None:
    """Run/RunOnce ve Winlogon gibi bilinen persistence registry alanlari."""
    persistence_keys = [
        "\\run\\",
        "\\runonce\\",
        "currentversion\\run",
        "currentversion\\runonce",
        "winlogon\\shell",
        "winlogon\\userinit",
    ]

    hits = []

    for e in events:
        if e.get("event_type") != "sysmon_registry_event":
            continue

        target = str(
            _normalized_or_raw(
                e,
                "registry_target",
                "targetObject",
            )
            or ""
        ).lower()

        if any(key in target for key in persistence_keys):
            hits.append(e)

    if not hits:
        return None

    return {
        "incident_type": "registry_persistence_attempt",
        "matched_events": hits,
        "base_risk": 65,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1547.001",
                "tactic": "Persistence",
                "technique": "Registry Run Keys / Startup Folder",
            }
        ],
    }


def detect_scheduled_task_creation(events: list[dict]) -> dict | None:
    """schtasks.exe /create veya PowerShell scheduled-task olusturma paterni."""
    hits = []

    for e in events:
        process = _process_name(e.get("process"))
        cmd = (e.get("command_line") or "").lower()

        schtasks_create = (
            process.endswith("schtasks.exe")
            and "/create" in cmd
        )

        powershell_task = (
            "register-scheduledtask" in cmd
            or "new-scheduledtask" in cmd
        )

        if schtasks_create or powershell_task:
            hits.append(e)

    hits = _unique_events(hits)

    if not hits:
        return None

    return {
        "incident_type": "scheduled_task_persistence",
        "matched_events": hits,
        "base_risk": 55,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1053.005",
                "tactic": "Persistence",
                "technique": "Scheduled Task/Job: Scheduled Task",
            }
        ],
    }


def detect_new_local_account(events: list[dict]) -> dict | None:
    """Komut satirindan yeni yerel hesap olusturma paterni."""
    hits = []

    for e in events:
        cmd = (e.get("command_line") or "").lower()

        if (
            ("net user" in cmd and "/add" in cmd)
            or "new-localuser" in cmd
        ):
            hits.append(e)

    hits = _unique_events(hits)

    if not hits:
        return None

    return {
        "incident_type": "new_local_account_created",
        "matched_events": hits,
        "base_risk": 55,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1136.001",
                "tactic": "Persistence",
                "technique": "Create Account: Local Account",
            }
        ],
    }


# ============================================================
# KATEGORI: DEFENSE EVASION
# ============================================================


def detect_defender_tampering(events: list[dict]) -> dict | None:
    """Windows Defender'i devre disi birakma veya zayiflatma girisimleri."""
    flags = [
        "disablerealtimemonitoring",
        "set-mppreference",
        "disableantispyware",
        "add-mppreference -exclusionpath",
        "disableioavprotection",
    ]

    hits = _unique_events(
        _cmdline_contains_any(events, flags)
    )

    if not hits:
        return None

    return {
        "incident_type": "defender_tampering_attempt",
        "matched_events": hits,
        "base_risk": 80,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1562.001",
                "tactic": "Defense Evasion",
                "technique": "Impair Defenses",
            }
        ],
    }


def detect_log_clearing(events: list[dict]) -> dict | None:
    """Windows event log temizleme davranisi."""
    flags = [
        "wevtutil cl",
        "wevtutil.exe cl",
        "clear-eventlog",
        "clear-log",
        "remove-eventlog",
    ]

    hits = _unique_events(
        _cmdline_contains_any(events, flags)
    )

    if not hits:
        return None

    return {
        "incident_type": "log_clearing_attempt",
        "matched_events": hits,
        "base_risk": 85,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1070.001",
                "tactic": "Defense Evasion",
                "technique": "Clear Windows Event Logs",
            }
        ],
    }


def detect_suspicious_file_drop(events: list[dict]) -> dict | None:
    """Riskli dizinlere executable/script dosyasi olusturulmasini tespit eder."""
    risky_dirs = [
        "\\downloads\\",
        "\\temp\\",
        "\\appdata\\local\\temp\\",
        "\\users\\public\\",
    ]

    risky_ext = (
        ".exe",
        ".dll",
        ".ps1",
        ".bat",
        ".vbs",
        ".scr",
    )

    hits = []

    for e in events:
        if e.get("event_type") != "sysmon_file_create":
            continue

        filename = (e.get("target_filename") or "").lower()

        if (
            any(directory in filename for directory in risky_dirs)
            and filename.endswith(risky_ext)
        ):
            hits.append(e)

    hits = _unique_events(hits)

    if not hits:
        return None

    return {
        "incident_type": "suspicious_file_drop",
        "matched_events": hits,
        "base_risk": 50,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1105",
                "tactic": "Command and Control",
                "technique": "Ingress Tool Transfer",
            }
        ],
    }


# ============================================================
# KATEGORI: DISCOVERY / NETWORK
# ============================================================


def detect_port_scan(events: list[dict]) -> dict | None:
    """
    Ayni kaynak IP'den 5+ farkli destination port gorulmesi.

    Correlation window suresini agent belirledigi icin burada ayrica zaman
    hesaplamasi yapilmaz.
    """
    net_events = [
        e for e in events
        if e.get("event_type") == "sysmon_network_connection"
    ]

    if not net_events:
        return None

    by_source_ip = {}

    for e in net_events:
        source_ip = e.get("source_ip") or "UNKNOWN"

        port = _normalized_or_raw(
            e,
            "destination_port",
            "destinationPort",
        )

        if source_ip == "UNKNOWN" or port in (None, ""):
            continue

        port = str(port)

        bucket = by_source_ip.setdefault(
            source_ip,
            {
                "events": [],
                "ports": set(),
            }
        )

        bucket["events"].append(e)
        bucket["ports"].add(port)

    candidates = []

    for source_ip, data in by_source_ip.items():
        if len(data["ports"]) >= 5:
            candidates.append(data)

    if not candidates:
        return None

    # En fazla farkli porta temas eden kaynak en guclu aday.
    best = max(
        candidates,
        key=lambda item: len(item["ports"])
    )

    hits = _unique_events(best["events"])

    return {
        "incident_type": "possible_port_scan",
        "matched_events": hits,
        "base_risk": 50,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1046",
                "tactic": "Discovery",
                "technique": "Network Service Discovery",
            }
        ],
    }


def detect_uncommon_outbound_port(events: list[dict]) -> dict | None:
    """
    Standart olmayan yuksek destination portlara baslatilan cikis baglantilari.
    Tek basina C2 kaniti degildir; dusuk-orta seviye korelasyon sinyalidir.
    """
    hits = []

    for e in events:
        if e.get("event_type") != "sysmon_network_connection":
            continue

        raw_port = _normalized_or_raw(
            e,
            "destination_port",
            "destinationPort",
        )

        try:
            port = int(raw_port or 0)
        except (ValueError, TypeError):
            continue

        initiated_raw = _get_eventdata_field(
            e,
            "initiated"
        )

        initiated = str(initiated_raw).lower() == "true"

        if (
            initiated
            and port > 1024
            and port not in COMMON_PORTS
        ):
            hits.append(e)

    hits = _unique_events(hits)

    if len(hits) < 3:
        return None

    return {
        "incident_type": "uncommon_outbound_connections",
        "matched_events": hits,
        "base_risk": 30,
        "mitre": _collect_mitre(hits) or [
            {
                "id": "T1071",
                "tactic": "Command and Control",
                "technique": "Application Layer Protocol",
            }
        ],
    }


# ============================================================
# KATEGORI: DUSUK SEVIYE / BILGILENDIRME
# ============================================================


def detect_single_failed_login(events: list[dict]) -> dict | None:
    """1-4 basarisiz login denemesini dusuk riskli sinyal olarak tut."""
    failures = [
        e for e in events
        if e.get("event_type") == "authentication_failure"
    ]

    if not (1 <= len(failures) < 5):
        return None

    return {
        "incident_type": "single_failed_login",
        "matched_events": failures,
        "base_risk": 10,
        "mitre": _collect_mitre(failures) or [
            {
                "id": "T1078",
                "tactic": "Initial Access",
                "technique": "Valid Accounts",
            }
        ],
    }


# ============================================================
# GUVENLIK AGI: WAZUH HIGH-SEVERITY PASSTHROUGH
# ============================================================


def pass_through_high_severity_wazuh_rule(events: list[dict]) -> dict | None:
    """
    AegisAI'nin spesifik kurallari disinda kalan Wazuh level >= 10
    alarmlarinin da gozden kacmamasini saglayan genel guvenlik agi.
    """
    high_sev = [
        e for e in events
        if (e.get("wazuh_rule_level") or 0) >= 10
    ]

    high_sev = _unique_events(high_sev)

    if not high_sev:
        return None

    return {
        "incident_type": "wazuh_high_severity_alert",
        "matched_events": high_sev,
        "base_risk": 65,
        "mitre": _collect_mitre(high_sev),
    }


# ============================================================
# KURAL LISTESI
# ============================================================

ALL_RULES = [
    detect_defender_tampering,
    detect_log_clearing,
    detect_lsass_access,
    detect_credential_file_access,
    detect_registry_persistence,
    detect_new_local_account,
    detect_scheduled_task_creation,
    detect_living_off_the_land,
    detect_suspicious_process_chain,
    detect_suspicious_powershell,
    detect_suspicious_file_drop,
    detect_brute_force,
    detect_port_scan,
    detect_uncommon_outbound_port,
    pass_through_high_severity_wazuh_rule,
    detect_single_failed_login,
]


def evaluate_all(events: list[dict]) -> list[dict]:
    """
    Tum kurallari degerlendirir ve tum eslesmeleri dondurur.

    Eski 'ilk eslesen kazanir' modeline alternatif olarak agent.py tarafinda
    multi-rule correlation icin kullanilabilir.

    Spesifik bir AegisAI kurali eslesmisse genel Wazuh passthrough sonucu
    ayni pencere icin tekrar incident uretmesin diye filtrelenir.
    """
    matches = []

    for rule in ALL_RULES:
        try:
            result = rule(events)
        except Exception as exc:
            print(
                f"[RULE ERROR] {rule.__name__}: "
                f"{type(exc).__name__}: {exc}"
            )
            continue

        if result:
            matches.append(result)

    if not matches:
        return []

    specific_matches = [
        result
        for result in matches
        if result.get("incident_type")
        != "wazuh_high_severity_alert"
    ]

    if specific_matches:
        matches = [
            result
            for result in matches
            if result.get("incident_type")
            != "wazuh_high_severity_alert"
        ]

    return matches
