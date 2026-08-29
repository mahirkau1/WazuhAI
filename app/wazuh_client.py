import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhIndexerClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)

    def get_alerts_since(self, since_iso: str, min_level: int = 3, size: int = 200):
        """
        Wazuh Indexer'daki wazuh-alerts-* index'inden, belirtilen zamandan
        sonraki, belirli bir seviyenin uzerindeki alarmlari ceker.
        """
        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gt": since_iso}}},
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
        }
        resp = requests.post(
            f"{self.base_url}/wazuh-alerts-*/_search",
            json=query,
            auth=self.auth,
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]
