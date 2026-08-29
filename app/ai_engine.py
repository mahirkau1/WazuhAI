import os
import json
import anthropic

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

INCIDENT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["suspicious", "benign", "insufficient_evidence"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "attack_name": {
            "type": "string",
            "description": "Bu saldiri tipinin bilinen/yaygin adi (orn. 'Credential Dumping via LSASS Access')"
        },
        "mitre": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string"},
                    "name": {"type": "string"}
                },
                "required": ["technique", "name"]
            }
        },
        "summary": {
            "type": "string",
            "description": "Olayin 2-3 cumlelik ozeti, teknik olmayan biri de anlayabilsin"
        },
        "evidence": {"type": "array", "items": {"type": "string"}},
        "is_known_pattern": {
            "type": "boolean",
            "description": "Bu, guvenlik literaturunde iyi bilinen, standart bir saldiri patern mi"
        },
        "similar_known_attacks": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Eger biliniyorsa, bu teknigi kullanan bilinen kampanya/grup/malware isimleri"
        },
        "remediation_steps": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Bu spesifik olayi kapatmak icin somut, uygulanabilir adimlar"
        },
        "prevention_recommendations": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Bu tip saldirilarin gelecekte tekrar olmasini onlemek icin genel oneriler"
        }
    },
    "required": [
        "verdict", "confidence", "severity", "attack_name", "mitre",
        "summary", "evidence", "is_known_pattern", "similar_known_attacks",
        "remediation_steps", "prevention_recommendations"
    ]
}

SYSTEM_PROMPT = """Sen deneyimli bir SOC analisti ve olay mudahale (incident response)
uzmanisin. Tek bir Windows 10 makinesinden (workgroup ortami, Active Directory
yok, lab/gelistirme amacli) gelen Wazuh alarmlarini analiz ediyorsun.

Wazuh'un kendi kural motoru zaten bir on-siniflandirma yapmis olabilir
(wazuh_rule_description, wazuh_mitre alanlarina bak) -- bunu bir baslangic
noktasi olarak kullan, ama kendi bagimsiz degerlendirmeni de yap.

KURALLAR:
- Sana verilmeyen hicbir kanit uydurma, sadece saglanan telemetriyi kullan.
- Kanit yetersizse verdict alanina "insufficient_evidence" yaz.
- remediation_steps somut ve uygulanabilir olmali (orn. "LSASS process'ine
  PPL (Protected Process Light) korumasi ekleyin" gibi, "guvenligi artirin"
  gibi belirsiz ifadeler degil).
- is_known_pattern ve similar_known_attacks alanlarini doldururken,
  genel bilgi seviyende (training verinde) yer alan, iyi bilinen teknikler
  ve malware/kampanya isimlerine referans ver -- ama emin olmadigin
  spesifik iddialar yapma.
- Bu tek-host bir lab/gelistirme ortami olabilir; Atomic Red Team gibi
  guvenlik test araclarinin davranis imzalari gorulebilir, bunu da
  belirt (suspicious olabilir ama kontrollu bir test de olabilir)."""


def analyze_incident(incident_context: dict) -> dict:
    response = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=2000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(incident_context, ensure_ascii=False)}],
        output_config={"format": {"type": "json_schema", "schema": INCIDENT_SCHEMA}}
    )
    return json.loads(response.content[0].text)
