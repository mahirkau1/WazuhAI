import os
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

from wazuh_client import WazuhIndexerClient
from normalize import normalize_alert
from rules import ALL_RULES
import storage
import ai_engine

WAZUH_URL = os.environ["WAZUH_INDEXER_URL"]
WAZUH_USER = os.environ["WAZUH_INDEXER_USER"]
WAZUH_PASSWORD = os.environ["WAZUH_INDEXER_PASSWORD"]
AI_THRESHOLD = int(os.environ.get("AI_RISK_THRESHOLD", 60))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", 30))

client = WazuhIndexerClient(WAZUH_URL, WAZUH_USER, WAZUH_PASSWORD)


def calculate_risk_score(incident_draft: dict) -> int:
    base = incident_draft["base_risk"]
    event_count_bonus = min(len(incident_draft["matched_events"]) * 3, 20)
    asset_bonus = 10
    return min(base + event_count_bonus + asset_bonus, 100)


def evaluate_rules(events: list[dict]) -> dict | None:
    for rule in ALL_RULES:
        result = rule(events)
        if result:
            return result
    return None


def process_new_alerts(last_seen_timestamp: str) -> str:
    """Yeni alarmlari ceker, isler. En son gorulen timestamp'i doner."""
    alerts = client.get_alerts_since(last_seen_timestamp)
    if not alerts:
        return last_seen_timestamp

    newest_timestamp = last_seen_timestamp

    for raw in alerts:
        normalized = normalize_alert(raw)
        if normalized is None:
            continue

        newest_timestamp = max(newest_timestamp, normalized["timestamp"])

        if storage.is_duplicate(normalized["fingerprint"]):
            continue

        storage.save_event(normalized)
        print(f"[EVENT] {normalized['event_type']} | {normalized['host']} | "
              f"rule_level={normalized.get('wazuh_rule_level')}")

        related = storage.get_related_events(
            host=normalized["host"], username=normalized["username"], window_minutes=5
        )
        incident_draft = evaluate_rules(related)

        if incident_draft:
            risk_score = calculate_risk_score(incident_draft)
            host = incident_draft["matched_events"][0]["host"]
            username = incident_draft["matched_events"][0]["username"]
            incident_id = storage.create_incident(
                incident_draft["incident_type"], risk_score, host, username
            )
            print(f"[INCIDENT] #{incident_id} {incident_draft['incident_type']} "
                  f"risk={risk_score}")

            if risk_score >= AI_THRESHOLD:
                print(f"[AI] Incident #{incident_id} Claude'a gonderiliyor...")
                context = {
                    "incident_id": incident_id,
                    "host": host,
                    "username": username,
                    "risk_score": risk_score,
                    "events": [
                        {
                            "type": e["event_type"],
                            "event_id": e["event_id"],
                            "timestamp": e["timestamp"],
                            "wazuh_rule_description": e.get("wazuh_rule_description"),
                            "wazuh_mitre": e.get("raw_event", {}).get("rule", {}).get("mitre", {}),
                            **({"process": e["process"]} if e.get("process") else {}),
                            **({"command_line": e["command_line"]} if e.get("command_line") else {}),
                        }
                        for e in incident_draft["matched_events"]
                    ],
                }
                try:
                    ai_result = ai_engine.analyze_incident(context)
                    storage.save_ai_result(incident_id, ai_result)
                    print(f"[AI] Incident #{incident_id} analiz tamamlandi: "
                          f"{ai_result.get('attack_name')} ({ai_result.get('verdict')})")
                except Exception as ex:
                    print(f"[AI HATASI] {ex}")

    return newest_timestamp


def main():
    storage.init_db()
    print(f"AegisAI Agent basladi. Wazuh: {WAZUH_URL}, "
          f"poll interval: {POLL_INTERVAL}s, AI threshold: {AI_THRESHOLD}")

    last_seen = (datetime.utcnow() - timedelta(minutes=5)).isoformat()

    while True:
        try:
            last_seen = process_new_alerts(last_seen)
        except Exception as ex:
            print(f"[HATA] Poll dongusu basarisiz: {ex}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
