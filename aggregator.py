"""Core aggregator: dispatches an indicator to every applicable source."""
from .config import load_api_keys
from .detector import detect_type
from .sources.abuseipdb import AbuseIPDBSource
from .sources.urlscan import UrlscanSource
from .sources.virustotal import VirusTotalSource

SOURCE_CLASSES = [VirusTotalSource, AbuseIPDBSource, UrlscanSource]


def build_sources(api_keys=None):
    """Instantiate all source classes with their configured API keys."""
    if api_keys is None:
        api_keys = load_api_keys()
    return [cls(api_key=api_keys.get(cls.name)) for cls in SOURCE_CLASSES]


def scan_indicator(indicator, api_keys=None, only_sources=None):
    """Run one indicator against every applicable source.

    Returns a dict with the detected type and a list of per-source results.
    """
    indicator = indicator.strip()
    indicator_type = detect_type(indicator)

    if indicator_type is None:
        return {
            "indicator": indicator,
            "type": None,
            "results": [],
            "error": "Could not determine indicator type.",
        }

    sources = build_sources(api_keys)
    if only_sources:
        sources = [s for s in sources if s.name in only_sources]

    results = []
    for source in sources:
        if not source.supports(indicator_type):
            continue
        results.append(source.query(indicator, indicator_type))

    return {"indicator": indicator, "type": indicator_type, "results": results}
