import os
import json
from typing import Any

import anthropic


# ============================================================
# AYARLAR
# ============================================================

MODEL = os.environ.get(
    "ANTHROPIC_MODEL",
    "claude-sonnet-5",
)

MAX_TOKENS = int(
    os.environ.get(
        "ANTHROPIC_MAX_TOKENS",
        "4000",
    )
)

TOOL_NAME = "report_incident_analysis"


# ============================================================
# ANTHROPIC CLIENT
# ============================================================

def _get_client() -> anthropic.Anthropic:
    """
    Client'i import aninda degil, gercek AI cagrisi yapilacagi zaman
    olusturur. Boylece API anahtari eksikse agent import'u gereksiz
    yere patlamaz; hata AI cagrisi sirasinda acikca gorulur.
    """
    api_key = os.environ.get(
        "ANTHROPIC_API_KEY"
    )

    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY tanimli degil."
        )

    return anthropic.Anthropic(
        api_key=api_key
    )


# ============================================================
# STRUCTURED OUTPUT TOOL
# ============================================================

ANALYSIS_TOOL = {
    "name": TOOL_NAME,
    "description": (
        "Saglanan guvenlik telemetrisiyle sinirli, "
        "kanita dayali ve yapilandirilmis incident analizi raporla."
    ),
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "verdict": {
                "type": "string",
                "enum": [
                    "suspicious",
                    "benign",
                    "insufficient_evidence",
                ],
            },

            "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
            },

            "severity": {
                "type": "string",
                "enum": [
                    "low",
                    "medium",
                    "high",
                    "critical",
                ],
                "description": (
                    "AI'nin analitik severity tahmini. "
                    "AegisAI'nin deterministik risk_score/severity "
                    "degerini DEGISTIRMEZ."
                ),
            },

            "attack_name": {
                "type": "string",
                "description": (
                    "Kanita gore davranisin en uygun teknik adi. "
                    "Kanit yetersizse bunu acikca ifade et."
                ),
            },

            "what_happened": {
                "type": "string",
                "description": (
                    "Saglanan event'lerden cikabilen olayi 3-5 cumleyle "
                    "acikla. Telemetride olmayan surec, IP, domain, dosya, "
                    "kullanici veya arac uydurma."
                ),
            },

            "why_flagged": {
                "type": "string",
                "description": (
                    "Hangi somut event/alanlarin olayi supheli veya "
                    "onemli hale getirdigini acikla."
                ),
            },

            "mitre": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "Orn. T1003.001",
                        },
                        "technique_name": {
                            "type": "string",
                        },
                        "tactic": {
                            "type": "string",
                        },
                    },
                    "required": [
                        "technique_id",
                        "technique_name",
                        "tactic",
                    ],
                },
            },

            "evidence": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": (
                    "Her madde saglanan belirli bir event/alana "
                    "dayansin. Olmayan IOC/telemetri uydurma."
                ),
            },

            "is_known_pattern": {
                "type": "boolean",
            },

            "similar_known_attacks": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": (
                    "Yalnizca davranis paterniyle gercekten iliskili "
                    "bilinen arac/malware/kampanya ornekleri. "
                    "Bunlari bu incident'ta kullanilmis gibi sunma."
                ),
            },

            "immediate_actions": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": (
                    "Savunmaya yonelik, geri alinabilir ve mumkunse "
                    "insan onayli olay mudahale adimlari."
                ),
            },

            "prevention_recommendations": {
                "type": "array",
                "items": {
                    "type": "string"
                },
            },

            "false_positive_likelihood": {
                "type": "string",
                "enum": [
                    "low",
                    "medium",
                    "high",
                ],
            },
        },

        "required": [
            "verdict",
            "confidence",
            "severity",
            "attack_name",
            "what_happened",
            "why_flagged",
            "mitre",
            "evidence",
            "is_known_pattern",
            "similar_known_attacks",
            "immediate_actions",
            "prevention_recommendations",
            "false_positive_likelihood",
        ],
    },
}


# ============================================================
# SYSTEM PROMPT
# ============================================================

SYSTEM_PROMPT = """
Sen AegisAI icinde calisan deneyimli bir SOC analisti ve incident-response
destek motorusun.

Sana Windows/Sysmon/PowerShell/Wazuh telemetrisi ve AegisAI'nin deterministik
detection sonuclari verilir. Gorevin karar mekanizmasinin yerine gecmek degil;
mevcut kanitlari aciklamak, korelasyonu yorumlamak ve analiste destek olmaktir.

ONEMLI OTORITE SINIRI:
- risk_score AegisAI'nin deterministik kural motoru tarafindan hesaplanmistir.
- Bu skoru degistiremezsin.
- "severity" alanin yalnizca analitik gorusundur.
- Wazuh ve AegisAI detection etiketleri kanittir ama otomatik olarak dogru
  kabul edilmez; event telemetrisiyle birlikte degerlendirilir.

KANIT DISIPLİNİ:
1. Sana verilmeyen hicbir gercegi UYDURMA.
2. Process adi, PID, parent process, command line, IP, port, domain, DNS,
   dosya yolu, hash, registry key, SID, kullanici veya IOC ancak input'ta
   mevcutsa somut kanit gibi yazilabilir.
3. Bir alan yoksa "muhtemelen", "kesinlikle" veya benzeri ifadelerle onu
   doldurma.
4. Kanit yetersizse verdict="insufficient_evidence" kullan.
5. Supheli bir teknik gorulmesi tek basina gercek compromise kaniti degildir.
6. Benzer bilinen arac/malware isimleri verilebilir ancak bunlari incident'ta
   gercekten kullanilmis gibi sunma. Ornegin:
   "Bu teknik Mimikatz gibi araclarla iliskilidir" denebilir;
   "Mimikatz calistirildi" ancak telemetride bunu gosteren kanit varsa denebilir.

KORELASYON:
- matched_detection_rules birden fazla AegisAI kuralinin ayni korelasyon
  penceresinde eslestigini gosterebilir.
- Event'leri timestamp, host, username, process/process_guid,
  parent_process_guid, source/destination network alanlari ve diger mevcut
  telemetry uzerinden iliskilendir.
- Aynı zaman penceresinde bulunmak tek basina nedensellik kaniti degildir.
- events_truncated=true ise tum event setini gormedigini acikca hesaba kat.

MITRE:
- MITRE technique ID'lerini yalnizca saglanan kanit veya acik bir davranis
  eslesmesi destekliyorsa ekle.
- Wazuh/AegisAI MITRE etiketini kontrol et; sadece etiket var diye yeni
  teknikler uydurma.
- Sub-technique kaniti yoksa gereksiz yere asiri spesifik sub-technique secme.

FALSE POSITIVE / LAB:
- Ortam lab/gelistirme veya guvenlik testi olabilir.
- Atomic Red Team, yonetici islemi, IT otomasyonu veya test davranisi olasiligi
  varsa bunu false_positive_likelihood alanina yansit.
- Ancak sirf lab ortaminda oldugu icin supheli davranisi benign sayma.
- Gercek saldirgan ile test ayni teknigi uretebilir; teknik siniflandirmayi
  kanita gore yap.

IMMEDIATE ACTIONS:
- Savunmaya yonelik ve uygulanabilir ol.
- Telemetride olmayan PID/IP/kullanici gibi ayrintilari uydurarak komut verme.
- Yikici veya geri dondurulemez otomasyonu varsayma.
- Izolasyon, process sonlandirma, hesap devre disi birakma gibi etkili
  aksiyonlari "analist/onay sonrasi" baglaminda oner.
- Once kaniti koruma ve kapsam dogrulama, sonra containment, ardindan
  eradication/recovery mantigini kullan.

CIKTI:
- Yalnizca report_incident_analysis tool'unu kullan.
- Tool schema'sindaki butun zorunlu alanlari doldur.
- Acik, teknik ve kisa ol.
""".strip()


# ============================================================
# SONUC DOGRULAMA
# ============================================================

_REQUIRED_FIELDS = {
    "verdict",
    "confidence",
    "severity",
    "attack_name",
    "what_happened",
    "why_flagged",
    "mitre",
    "evidence",
    "is_known_pattern",
    "similar_known_attacks",
    "immediate_actions",
    "prevention_recommendations",
    "false_positive_likelihood",
}

_VALID_VERDICTS = {
    "suspicious",
    "benign",
    "insufficient_evidence",
}

_VALID_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
}

_VALID_FP = {
    "low",
    "medium",
    "high",
}


def _validate_ai_result(
    result: Any
) -> dict:
    """
    API tool schema'si zaten guclu bir ilk koruma saglar.
    Buna ek olarak uygulama tarafinda temel tip/deger kontrolu yapar.
    """
    if not isinstance(result, dict):
        raise RuntimeError(
            "AI tool sonucu dict degil."
        )

    missing = (
        _REQUIRED_FIELDS
        - set(result.keys())
    )

    if missing:
        raise RuntimeError(
            "AI sonucunda zorunlu alanlar eksik: "
            + ", ".join(
                sorted(missing)
            )
        )

    if result["verdict"] not in _VALID_VERDICTS:
        raise RuntimeError(
            "Gecersiz AI verdict degeri."
        )

    if result["severity"] not in _VALID_SEVERITIES:
        raise RuntimeError(
            "Gecersiz AI severity degeri."
        )

    if (
        result["false_positive_likelihood"]
        not in _VALID_FP
    ):
        raise RuntimeError(
            "Gecersiz false_positive_likelihood."
        )

    confidence = result["confidence"]

    if not isinstance(
        confidence,
        (int, float),
    ):
        raise RuntimeError(
            "AI confidence sayisal degil."
        )

    if not 0 <= float(confidence) <= 1:
        raise RuntimeError(
            "AI confidence 0-1 araliginda degil."
        )

    if not isinstance(
        result["is_known_pattern"],
        bool,
    ):
        raise RuntimeError(
            "is_known_pattern boolean degil."
        )

    list_fields = [
        "mitre",
        "evidence",
        "similar_known_attacks",
        "immediate_actions",
        "prevention_recommendations",
    ]

    for field in list_fields:
        if not isinstance(
            result[field],
            list,
        ):
            raise RuntimeError(
                f"AI sonucu {field} list degil."
            )

    text_fields = [
        "attack_name",
        "what_happened",
        "why_flagged",
    ]

    for field in text_fields:
        if not isinstance(
            result[field],
            str,
        ):
            raise RuntimeError(
                f"AI sonucu {field} string degil."
            )

    return result


# ============================================================
# INCIDENT ANALIZI
# ============================================================

def analyze_incident(
    incident_context: dict
) -> dict:
    """
    Incident context'ini Claude'a yollar.

    Tool forcing sayesinde serbest metin yerine schema'ya uygun
    yapilandirilmis bir tool_use sonucu bekler.

    Hata olursa exception yukariya firlatilir. agent.py bu hatayi
    loglar ve incidents.ai_error alanina kaydeder.
    """
    if not isinstance(
        incident_context,
        dict,
    ):
        raise TypeError(
            "incident_context dict olmali."
        )

    client = _get_client()

    serialized_context = json.dumps(
        incident_context,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )

    response = client.messages.create(
        model=MODEL,

        # Sonnet 5'te adaptive thinking varsayilan olarak acik.
        # Bu is structured SOC extraction/analysis oldugu icin
        # daha tahmin edilebilir tool-output davranisi ve daha
        # kontrollu token kullanimi icin kapatiyoruz.
        thinking={
            "type": "disabled"
        },

        max_tokens=MAX_TOKENS,

        system=SYSTEM_PROMPT,

        tools=[
            ANALYSIS_TOOL
        ],

        tool_choice={
            "type": "tool",
            "name": TOOL_NAME,
        },

        messages=[
            {
                "role": "user",
                "content": serialized_context,
            }
        ],
    )

    for block in response.content:
        if (
            getattr(
                block,
                "type",
                None,
            )
            == "tool_use"
            and getattr(
                block,
                "name",
                None,
            )
            == TOOL_NAME
        ):
            return _validate_ai_result(
                block.input
            )

    stop_reason = getattr(
        response,
        "stop_reason",
        None,
    )

    raise RuntimeError(
        "Claude beklenen tool_use blogunu dondurmedi. "
        f"stop_reason={stop_reason!r}"
    )
