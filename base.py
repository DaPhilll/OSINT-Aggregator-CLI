"""Base interface for all OSINT source modules."""
from abc import ABC, abstractmethod


class OSINTSource(ABC):
    """Common interface every source module implements.

    Each source declares which indicator types it supports and returns a
    normalized result dictionary so the aggregator can treat all sources
    the same way.
    """

    name = "base"
    supported_types = []  # e.g. ["ip", "domain", "url"]

    def __init__(self, api_key=None):
        self.api_key = api_key

    def supports(self, indicator_type):
        return indicator_type in self.supported_types

    @abstractmethod
    def query(self, indicator, indicator_type):
        """Query the source for a single indicator.

        Returns a dict with at minimum:
            source (str), indicator (str), type (str), status (str),
            summary (str), and details (dict).
        status is one of: "ok", "not_found", "error", "skipped".
        """
        raise NotImplementedError

    def _result(self, indicator, indicator_type, status, summary, details=None):
        return {
            "source": self.name,
            "indicator": indicator,
            "type": indicator_type,
            "status": status,
            "summary": summary,
            "details": details or {},
        }
