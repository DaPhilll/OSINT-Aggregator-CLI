[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)

# OSINT Aggregator CLI

A command-line tool that queries multiple OSINT reputation sources for a single indicator from one place, instead of checking each provider's website separately. Give it an IP, domain, URL, email, or file hash, and it detects the type, routes the query to every applicable source, and returns the combined results.

## Repository Structure
```
/osint_aggregator
  __init__.py
  aggregator.py
  config.py
  detector.py
  /sources
    __init__.py
    base.py
    virustotal.py
    abuseipdb.py
    urlscan.py
cli.py
requirements.txt
.env.example
.gitignore
LICENSE
README.md
```

## Supported Sources

| Source | Indicator Types | API Key | Free Tier |
| :--- | :--- | :--- | :--- |
| VirusTotal | IP, domain, URL, hash | Required | Yes (rate limited) |
| AbuseIPDB | IP | Required | Yes (daily quota) |
| urlscan.io | domain, URL | Required | Yes (rate limited) |

The tool is built so that each source is a self-contained module implementing a common interface. Adding a new provider (for example, AlienVault OTX, GreyNoise, or EmailRep) means writing one new module and registering it, without changing the core logic.

## Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Copy the environment template and add your API keys:
   ```bash
   cp .env.example .env
   ```
3. Edit `.env` with your keys. The `.env` file is gitignored and must never be committed.

Keys are read from environment variables first, then from `.env`. Any source without a configured key is skipped rather than failing the run, so the tool works with whichever keys you have.

## Usage
```bash
# Auto-detect indicator type and query all applicable sources
python cli.py 8.8.8.8
python cli.py example.com
python cli.py https://example.com/path

# Raw JSON output for piping into other tools
python cli.py example.com --json

# Restrict to specific sources
python cli.py 8.8.8.8 --only abuseipdb,virustotal
```

### Example Output
```
Indicator: 8.8.8.8  (type: ip)
------------------------------------------------------------
[OK] virustotal: 0 malicious, 0 suspicious, 72 harmless
[OK] abuseipdb: Abuse confidence 0%, 12 reports, country US
```

Status labels: `[OK]` result returned, `[--]` no record found, `[ERR]` request failed, `[SKIP]` no API key configured for that source.

## Design Notes
* **Indicator detection** is handled centrally in `detector.py`, so every source receives an already-classified indicator and only runs when it supports that type.
* **Synchronous sources only** in this version. urlscan.io uses its Search API (existing scan data) rather than live scan submission, which is asynchronous. This keeps every source on the same request-and-return pattern. Live scanning can be added later as an option.
* **No hardcoded keys.** Credentials load from the environment or a gitignored `.env` file. `.env.example` documents the required variable names.
* **Rate limits.** The VirusTotal free tier is the tightest constraint (roughly 4 requests per minute, 500 per day). Confirm current limits in each provider's documentation before high-volume use.

## Roadmap
* [ ] Add EmailRep.io for email indicator support.
* [ ] Add AlienVault OTX and GreyNoise as additional IP and domain sources.
* [ ] Add optional caching to avoid repeat lookups of the same indicator within a session.
* [ ] Add batch mode to read indicators from a file.

## License
MIT — see [LICENSE](./LICENSE).

<br><br><br>
[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)
