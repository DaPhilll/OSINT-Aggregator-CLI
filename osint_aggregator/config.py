"""Loads API keys from environment variables or an optional .env file.

The .env file, if present, is read once at import. Environment variables
always take precedence over .env values. Keys are never hardcoded.
"""
import os

ENV_KEYS = {
    "virustotal": "VT_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "urlscan": "URLSCAN_API_KEY",
}


def _load_dotenv(path=".env"):
    """Populate os.environ from a .env file without overwriting existing vars."""
    if not os.path.exists(path):
        return
    with open(path, "r") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def load_api_keys():
    """Return a dict mapping source name to its API key (or None if unset)."""
    _load_dotenv()
    return {source: os.environ.get(env_var) for source, env_var in ENV_KEYS.items()}
