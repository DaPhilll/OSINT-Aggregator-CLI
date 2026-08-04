"""VirusTotal source module.

Supports IP, domain, URL, and file hash reputation via the VirusTotal v3 API.
Free tier is rate limited (roughly 4 requests per minute, 500 per day).
Reference: https://docs.virustotal.com/reference/overview
"""
import base64

import requests

from .base import OSINTSource

BASE_URL = "https://www.virustotal.com/api/v3"
TIMEOUT = 20


class VirusTotalSource(OSINTSource):
    name = "virustotal"
    supported_types = ["ip", "domain", "url", "hash"]

    def _endpoint(self, indicator, indicator_type):
        if indicator_type == "ip":
            return f"{BASE_URL}/ip_addresses/{indicator}"
        if indicator_type == "domain":
            return f"{BASE_URL}/domains/{indicator}"
        if indicator_type == "hash":
            return f"{BASE_URL}/files/{indicator}"
        if indicator_type == "url":
            # VirusTotal identifies a URL by its base64 (no padding) form.
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            return f"{BASE_URL}/urls/{url_id}"
        return None

    def query(self, indicator, indicator_type):
        if not self.api_key:
            return self._result(indicator, indicator_type, "skipped",
                                "No API key configured for VirusTotal.")

        endpoint = self._endpoint(indicator, indicator_type)
        if endpoint is None:
            return self._result(indicator, indicator_type, "skipped",
                                "Indicator type not supported by VirusTotal.")

        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(endpoint, headers=headers, timeout=TIMEOUT)
        except requests.RequestException as exc:
            return self._result(indicator, indicator_type, "error", str(exc))

        if response.status_code == 404:
            return self._result(indicator, indicator_type, "not_found",
                                "No record found on VirusTotal.")
        if response.status_code == 401:
            return self._result(indicator, indicator_type, "error",
                                "VirusTotal rejected the API key (401).")
        if response.status_code == 429:
            return self._result(indicator, indicator_type, "error",
                                "VirusTotal rate limit reached (429).")
        if response.status_code != 200:
            return self._result(indicator, indicator_type, "error",
                                f"Unexpected status code {response.status_code}.")

        stats = (
            response.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        summary = (
            f"{malicious} malicious, {suspicious} suspicious, {harmless} harmless"
        )
        return self._result(indicator, indicator_type, "ok", summary, stats)
