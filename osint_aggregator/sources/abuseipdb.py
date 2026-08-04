"""AbuseIPDB source module.

Supports IP reputation via the AbuseIPDB v2 API. Free tier allows a daily
quota of checks. Reference: https://docs.abuseipdb.com/
"""
import requests

from .base import OSINTSource

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 20


class AbuseIPDBSource(OSINTSource):
    name = "abuseipdb"
    supported_types = ["ip"]

    def query(self, indicator, indicator_type):
        if indicator_type != "ip":
            return self._result(indicator, indicator_type, "skipped",
                                "AbuseIPDB supports IP indicators only.")
        if not self.api_key:
            return self._result(indicator, indicator_type, "skipped",
                                "No API key configured for AbuseIPDB.")

        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": indicator, "maxAgeInDays": 90}

        try:
            response = requests.get(CHECK_URL, headers=headers, params=params,
                                    timeout=TIMEOUT)
        except requests.RequestException as exc:
            return self._result(indicator, indicator_type, "error", str(exc))

        if response.status_code == 401:
            return self._result(indicator, indicator_type, "error",
                                "AbuseIPDB rejected the API key (401).")
        if response.status_code == 429:
            return self._result(indicator, indicator_type, "error",
                                "AbuseIPDB rate limit reached (429).")
        if response.status_code != 200:
            return self._result(indicator, indicator_type, "error",
                                f"Unexpected status code {response.status_code}.")

        data = response.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        country = data.get("countryCode", "unknown")

        summary = (
            f"Abuse confidence {score}%, {reports} reports, country {country}"
        )
        return self._result(indicator, indicator_type, "ok", summary, data)
