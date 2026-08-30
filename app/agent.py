import os
import time
import traceback
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv(override=True)

from wazuh_client import WazuhIndexerClient
from normalize import normalize_alert
from rules import evaluate_all
import storage
import ai_engine


# ============================================================
# AYARLAR
# ============================================================

WAZUH_URL = os.environ["WAZUH_INDEXER_URL"]
WAZUH_USER = os.environ["WAZUH_INDEXER_USER"]
WAZUH_PASSWORD = os.environ["WAZUH_INDEXER_PASSWORD"]

AI_THRESHOLD = int(
    os.environ.get("AI_RISK_THRESHOLD", 60)
)

POLL_INTERVAL = int(
    os.environ.get("POLL_INTERVAL_SECONDS", 30)
)

INCIDENT_COOLDOWN_MINUTES = int(
    os.environ.get("INCIDENT_COOLDOWN_MINUTES", 15)
)

CORRELATION_WINDOW_MINUTES = int(
    os.environ.get("CORRELATION_WINDOW_MINUTES", 5)
)

MAX_AI_EVENTS = int(
    os.environ.get("MAX_AI_EVENTS", 30)
)


client = WazuhIndexerClient(
    WAZUH_URL,
    WAZUH_USER,
    WAZUH_PASSWORD,
)


# ============================================================
# YARDIMCI FONKSIYONLAR
# ============================================================

def _event_identity(event: dict) -> str:
    """
    Ayni eventi korelasyon listesinde birden fazla kez saymamak icin
    mümkün oldugunca stabil bir kimlik olusturur.
    """
    fingerprint = event.get("fingerprint")
    if fingerprint:
        return f"fp:{fingerprint}"

    db_id = event.get("id")
    if db_id is not None:
        return f"id:{db_id}"

    return "|".join([
        str(event.get("timestamp") or ""),
        str(event.get("event_type") or ""),
        str(event.get("event_id") or ""),
        str(event.get("host") or ""),
        str(event.get("username") or ""),
        str(event.get("process") or ""),
        str(event.get("command_line") or ""),
    ])


def _unique_events(events: list[dict]) -> list[dict]:
    seen = set()
    result = []

    for event in events:
        key = _event_identity(event)

        if key in seen:
            continue

        seen.add(key)
        result.append(event)

    return result


def _merge_mitre(rule_matches: list[dict]) -> list[dict]:
    """
    Tum eslesen kurallarin MITRE etiketlerini tekillestirir.
    """
    seen = set()
    result = []

    for match in rule_matches:
        for mitre in match.get("mitre", []) or []:
            technique_id = mitre.get("id")

            key = (
                technique_id,
                mitre.get("tactic"),
                mitre.get("technique"),
            )

            if key in seen:
                continue

            seen.add(key)
            result.append(mitre)

    return result


def _select_primary_match(
    rule_matches: list[dict]
) -> dict:
    """
    Tek incidents tablosu / tek incident_id modeli korunurken,
    birden fazla detection eslesmesi arasindan ana incident tipini secer.

    En yuksek base_risk kazanir.
    Esitlikte rules.py'deki evaluate_all sirasi korunur.
    """
    return max(
        rule_matches,
        key=lambda match: int(
            match.get("base_risk", 0)
        ),
    )


def build_correlated_incident(
    rule_matches: list[dict]
) -> dict | None:
    """
    Bir korelasyon penceresinde birden fazla kural eslesmesini
    tek bir incident taslaginda birlestirir.

    Boylece mevcut SQLite modelini bozmadan multi-rule correlation
    yapabiliriz ve ayni event'i birden fazla incident'e zorla baglamayiz.
    """
    if not rule_matches:
        return None

    primary = _select_primary_match(rule_matches)

    merged_events = _unique_events([
        event
        for match in rule_matches
        for event in match.get("matched_events", [])
    ])

    return {
        "incident_type": primary["incident_type"],
        "base_risk": int(
            primary.get("base_risk", 0)
        ),
        "matched_events": merged_events,
        "mitre": _merge_mitre(rule_matches),
        "matched_rule_types": [
            match.get("incident_type")
            for match in rule_matches
            if match.get("incident_type")
        ],
        "rule_count": len(rule_matches),
    }


def calculate_risk_score(
    incident_draft: dict
) -> int:
    """
    Deterministik risk skoru.

    - Ana kuralin base risk'i
    - Benzersiz event sayisi
    - Birden fazla detection'in ayni pencereye eslesmesi
    - Mevcut V2 davranisini korumak icin asset bonus

    AI bu skoru belirlemez veya degistirmez.
    """
    base = int(
        incident_draft.get("base_risk", 0)
    )

    event_count = len(
        incident_draft.get(
            "matched_events",
            []
        )
    )

    rule_count = int(
        incident_draft.get(
            "rule_count",
            1
        )
    )

    event_count_bonus = min(
        event_count * 3,
        20,
    )

    correlation_bonus = min(
        max(rule_count - 1, 0) * 8,
        20,
    )

    asset_bonus = 10

    return min(
        base
        + event_count_bonus
        + correlation_bonus
        + asset_bonus,
        100,
    )


def _compact_event_for_ai(
    event: dict
) -> dict:
    """
    AI'ya sadece gercekten mevcut olan telemetry alanlarini yollar.
    Bos alanlari gondermeyerek hem prompt'u kucultur hem de yorum
    sirasinda olmayan verilerin varmis gibi algilanmasini azaltir.
    """
    result = {
        "type": event.get("event_type"),
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "host": event.get("host"),
        "username": event.get("username"),
        "wazuh_rule_description": event.get(
            "wazuh_rule_description"
        ),
        "wazuh_rule_level": event.get(
            "wazuh_rule_level"
        ),
        "wazuh_mitre": event.get(
            "wazuh_mitre",
            []
        ),
    }

    optional_fields = [
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "protocol",

        "process",
        "process_id",
        "process_guid",
        "command_line",

        "parent_process_id",
        "parent_process_guid",
        "parent_image",
        "parent_command_line",

        "target_image",
        "target_process_id",
        "target_process_guid",
        "granted_access",

        "target_filename",

        "dns_query",

        "registry_target",
        "registry_details",

        "hashes",
        "integrity_level",

        "user_sid",
        "logon_id",
        "logon_type",
    ]

    for field in optional_fields:
        value = event.get(field)

        if value not in (
            None,
            "",
            [],
            {},
        ):
            result[field] = value

    return result


# ============================================================
# AI ANALIZI
# ============================================================

def run_ai_analysis(
    incident_id: int,
    host: str,
    username: str,
    risk_score: int,
    matched_events: list[dict],
    rule_mitre: list[dict],
    matched_rule_types: list[str],
):
    print(
        f"[AI] Incident #{incident_id} "
        f"AI analizine gonderiliyor..."
    )

    unique_events = _unique_events(
        matched_events
    )

    # Kontrolsuz buyuyen korelasyon pencerelerinin
    # AI prompt'unu gereksiz sisirmesini engelle.
    ai_events = unique_events[
        :MAX_AI_EVENTS
    ]

    context = {
        "incident_id": incident_id,
        "host": host,
        "username": username,
        "risk_score": risk_score,

        "matched_detection_rules": (
            matched_rule_types
        ),

        "wazuh_detected_mitre": (
            rule_mitre
        ),

        "event_count": len(
            unique_events
        ),

        "events_truncated": (
            len(unique_events)
            > len(ai_events)
        ),

        "events": [
            _compact_event_for_ai(event)
            for event in ai_events
        ],
    }

    try:
        ai_result = (
            ai_engine.analyze_incident(
                context
            )
        )

        storage.save_ai_result(
            incident_id,
            ai_result,
        )

        print(
            f"[AI] Incident #{incident_id} "
            f"tamamlandi: "
            f"{ai_result.get('attack_name')} "
            f"({ai_result.get('verdict')}, "
            f"guven={ai_result.get('confidence')})"
        )

    except Exception as ex:
        error_detail = (
            f"{type(ex).__name__}: {ex}"
        )

        print(
            f"[AI HATASI] "
            f"Incident #{incident_id}: "
            f"{error_detail}"
        )

        traceback.print_exc()

        try:
            storage.save_ai_error(
                incident_id,
                error_detail,
            )
        except Exception:
            print(
                "[DB HATASI] AI hata bilgisi "
                "veritabanina yazilamadi:"
            )
            traceback.print_exc()


# ============================================================
# INCIDENT / KORELASYON AKISI
# ============================================================

def _should_run_ai_for_existing(
    existing: dict,
    new_risk_score: int,
) -> bool:
    """
    Yeni incident acilmadan mevcut incident guncelleniyorsa
    AI'nin tekrar tekrar calismasini engeller.

    Ancak incident daha once AI esiginin altindaysa ve yeni
    korelasyonla esigi asiyorsa bir kez analiz yapilmasina izin verir.
    """
    if new_risk_score < AI_THRESHOLD:
        return False

    if existing.get("attack_name"):
        return False

    if existing.get("verdict"):
        return False

    if existing.get("ai_error"):
        return False

    old_risk = int(
        existing.get("risk_score")
        or 0
    )

    return old_risk < AI_THRESHOLD


def process_new_alerts(
    last_seen_timestamp: str
) -> str:

    alerts = client.get_alerts_since(
        last_seen_timestamp
    )

    if not alerts:
        return last_seen_timestamp

    newest_timestamp = (
        last_seen_timestamp
    )

    for raw in alerts:
        try:
            normalized = normalize_alert(
                raw
            )

            if normalized is None:
                continue

            event_timestamp = (
                normalized.get(
                    "timestamp"
                )
                or last_seen_timestamp
            )

            if event_timestamp > newest_timestamp:
                newest_timestamp = (
                    event_timestamp
                )

            fingerprint = (
                normalized.get(
                    "fingerprint"
                )
            )

            if (
                fingerprint
                and storage.is_duplicate(
                    fingerprint
                )
            ):
                continue

            # Mevcut event DB'ye henuz yazilmadi.
            # Korelasyonda kaybolmamasi icin mevcut pencereye
            # elle dahil ediyoruz.
            related = (
                storage.get_related_events(
                    host=normalized["host"],
                    username=normalized[
                        "username"
                    ],
                    window_minutes=(
                        CORRELATION_WINDOW_MINUTES
                    ),
                )
            )

            related_with_current = (
                [normalized]
                + related
            )

            # rules.py artik tum eslesmeleri donduruyor.
            rule_matches = evaluate_all(
                related_with_current
            )

            incident_draft = (
                build_correlated_incident(
                    rule_matches
                )
            )

            incident_id = None

            if incident_draft:
                risk_score = (
                    calculate_risk_score(
                        incident_draft
                    )
                )

                matched_events = (
                    incident_draft[
                        "matched_events"
                    ]
                )

                # Ana event yoksa bile guvenli fallback.
                primary_event = (
                    matched_events[0]
                    if matched_events
                    else normalized
                )

                host = (
                    primary_event.get(
                        "host"
                    )
                    or normalized["host"]
                )

                username = (
                    primary_event.get(
                        "username"
                    )
                    or normalized[
                        "username"
                    ]
                )

                rule_mitre = (
                    incident_draft.get(
                        "mitre",
                        [],
                    )
                )

                matched_rule_types = (
                    incident_draft.get(
                        "matched_rule_types",
                        [],
                    )
                )

                incident_type = (
                    incident_draft[
                        "incident_type"
                    ]
                )

                existing = (
                    storage.get_open_incident(
                        incident_type,
                        host,
                        username,
                        cooldown_minutes=(
                            INCIDENT_COOLDOWN_MINUTES
                        ),
                    )
                )

                if existing:
                    should_run_ai = (
                        _should_run_ai_for_existing(
                            existing,
                            risk_score,
                        )
                    )

                    storage.bump_incident_occurrence(
                        existing["id"],
                        risk_score,
                    )

                    incident_id = (
                        existing["id"]
                    )

                    print(
                        f"[EVENT] "
                        f"{normalized['event_type']} | "
                        f"{normalized['host']} | "
                        f"incident #{incident_id} "
                        f"guncellendi | "
                        f"rules="
                        f"{','.join(matched_rule_types)} | "
                        f"risk={risk_score} | "
                        f"occurrence="
                        f"{int(existing.get('occurrence_count') or 1) + 1}"
                    )

                    if should_run_ai:
                        run_ai_analysis(
                            incident_id,
                            host,
                            username,
                            risk_score,
                            matched_events,
                            rule_mitre,
                            matched_rule_types,
                        )

                else:
                    incident_id = (
                        storage.create_incident(
                            incident_type,
                            risk_score,
                            host,
                            username,
                            rule_mitre,
                        )
                    )

                    print(
                        f"[INCIDENT] "
                        f"#{incident_id} YENI: "
                        f"{incident_type} | "
                        f"risk={risk_score} | "
                        f"rules="
                        f"{','.join(matched_rule_types)}"
                    )

                    if (
                        risk_score
                        >= AI_THRESHOLD
                    ):
                        run_ai_analysis(
                            incident_id,
                            host,
                            username,
                            risk_score,
                            matched_events,
                            rule_mitre,
                            matched_rule_types,
                        )

            else:
                print(
                    f"[EVENT] "
                    f"{normalized['event_type']} | "
                    f"{normalized['host']} | "
                    f"rule_level="
                    f"{normalized.get('wazuh_rule_level')} "
                    f"(incident olusturmadi)"
                )

            # Event ancak korelasyon sonucu belli olduktan sonra
            # incident_id ile birlikte kaydedilir.
            storage.save_event(
                normalized,
                incident_id=incident_id,
            )

        except Exception:
            # Tek bir bozuk/uyumsuz alert tum batch'i durdurmasin.
            print(
                "[EVENT HATASI] "
                "Tek bir Wazuh eventi islenemedi:"
            )
            traceback.print_exc()

    return newest_timestamp


# ============================================================
# MAIN LOOP
# ============================================================

def main():
    storage.init_db()

    print(
        f"AegisAI Agent basladi. "
        f"Wazuh: {WAZUH_URL}"
    )

    print(
        f"Poll interval: "
        f"{POLL_INTERVAL}s | "
        f"AI threshold: "
        f"{AI_THRESHOLD} | "
        f"Incident cooldown: "
        f"{INCIDENT_COOLDOWN_MINUTES}dk | "
        f"Correlation window: "
        f"{CORRELATION_WINDOW_MINUTES}dk"
    )

    last_seen = (
        datetime.now(
            timezone.utc
        )
        - timedelta(minutes=5)
    ).isoformat()

    while True:
        try:
            last_seen = (
                process_new_alerts(
                    last_seen
                )
            )

        except Exception:
            print(
                "[HATA] Poll dongusu "
                "basarisiz:"
            )
            traceback.print_exc()

        time.sleep(
            POLL_INTERVAL
        )


if __name__ == "__main__":
    main()
