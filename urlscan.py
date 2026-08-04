"""urlscan.io source module.

Uses the urlscan.io Search API to retrieve existing scan data for a domain
or URL in a single synchronous request. Live scan submission (an asynchronous
submit-and-poll flow) is intentionally not used in this version to keep all
sources synchronous and consistent.

Reference: https://urlscan.io/docs/search/
"""
import requests

from .base import OSINTSource

SEARCH_URL = "https://urlscan.io/api/v1/search/"
TIMEOUT = 20


class UrlscanSource(OSINTSource):
    name = "urlscan"
    supported_types = ["domain", "url"]

    def query(self, indicator, indicator_type):
        if indicator_type not in self.supported_types:
            return self._result(indicator, indicator_type, "skipped",
                                "urlscan supports domain and URL indicators.")
        if not self.api_key:
            return self._result(indicator, indicator_type, "skipped",
                                "No API key configured for urlscan.")

        if indicator_type == "domain":
            query = f"domain:{indicator}"
        else:
            query = f'page.url:"{indicator}"'

        headers = {"API-Key": self.api_key}
        params = {"q": query, "size": 5}

        try:
            response = requests.get(SEARCH_URL, headers=headers, params=params,
                                    timeout=TIMEOUT)
        except requests.RequestException as exc:
            return self._result(indicator, indicator_type, "error", str(exc))

        if response.status_code == 401:
            return self._result(indicator, indicator_type, "error",
                                "urlscan rejected the API key (401).")
        if response.status_code == 429:
            return self._result(indicator, indicator_type, "error",
                                "urlscan rate limit reached (429).")
        if response.status_code != 200:
            return self._result(indicator, indicator_type, "error",
                                f"Unexpected status code {response.status_code}.")

        body = response.json()
        total = body.get("total", 0)

        if total == 0:
            return self._result(indicator, indicator_type, "not_found",
                                "No existing urlscan results found.")

        results = body.get("results", [])
        malicious_hits = sum(
            1 for r in results
            if r.get("verdicts", {}).get("overall", {}).get("malicious")
        )
        latest = results[0].get("task", {}).get("time", "unknown")

        summary = (
            f"{total} scan(s) on record, {malicious_hits} flagged malicious "
            f"in latest {len(results)}, most recent {latest}"
        )
        return self._result(indicator, indicator_type, "ok", summary,
                            {"total": total, "malicious_in_page": malicious_hits})
