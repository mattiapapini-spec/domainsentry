# Changelog

All notable changes to this project will be documented in this file.

## [4.0.0] - 2026-06-02

### Changed
- **Architecture**: Complete decomposition from monolith to 10 modular services
- **Dual deploy mode**: unified (single container, port 8000) and production (10 containers)
- Single Docker image, service selected via `SERVICE_NAME` environment variable

### Added
- **Unified app** — all 20 endpoints on one port, one `docker compose up`
- **Production compose** — `docker-compose.prod.yml` for separate container deployment
- **Feed Manager** (:8000) — Domain lists and whitelist management via API + txt files
- **DNS Intel** (:8001) — Full DNS + DMARC/DKIM/BIMI/CAA + subdomain enumeration
- **Cert Intel** (:8002) — Certificate Transparency via crt.sh + TLS live inspection
- **HTTP Fingerprint** (:8003) — Content hash, form detection, hidden element detection
- **WHOIS Intel** (:8004) — Structured WHOIS with LRU cache
- **Reputation** (:8005) — VirusTotal + OTX + SecurityTrails with risk scoring
- **Dnstwist Engine** (:8006) — Permutation scan via subprocess (version-agnostic)
- **Classifier** (:8007) — Auto-classification (parking/for_sale/legitimate/suspicious/needs_review) + baseline diffing
- **Orchestrator** (:8010) — Pipeline coordination with thread-safe locking
- **Event Publisher** (:8011) — NDJSON file output + webhook support
- Hidden element detection: hidden forms, invisible iframes, obfuscated JS, meta redirects, tracking pixels, base64 content, staged code in comments
- Legitimate domain compromise detection (CRITICAL alerts for hidden elements on client's own domain)
- Domain input validation (RFC-compliant regex) on all endpoints
- Path traversal protection on feed manager
- Atomic file writes to prevent data corruption
- Swagger UI auto-generated on `/docs` for every service

## [3.1.0] - 2026-04-19

### Added
- WHOIS Intelligence module with baseline diffing
- Reputation check: VirusTotal, AlienVault OTX, SecurityTrails
- Risk scoring aggregated 0-100
- Watchlist monitoring for all dnstwist variants
- Whitelist management (CLI: whitelist add/remove/list)
- SQLite distributed locking with heartbeat and TTL
- Secrets management (env vars, Docker secrets, .env files)
- SOC Events with versioned NDJSON schema
- Content hash canonicalization (normalize_html_for_fingerprint)
- Two-step content change confirmation to reduce false positives
- Supply chain hardening with requirements.lock

## [3.0.0] - 2026-04-07

### Added
- Multi-client architecture with ClientManager
- Per-client isolated directories and configuration
- dnstwist integration via Python API (Module 7)
- CLI subcommands: client add/list/remove, run --client/--all
- Docker containerization with dual cron scheduling
- Healthcheck integrated in container

## [2.1.0] - 2026-04-06

### Added
- Lockfile anti-concurrency (fcntl)
- Retry with exponential backoff
- SAN auto-discovery from certificates
- DKIM check on 17 selectors
- CAA, BIMI, SOA record checks
- TLS live inspection
- Log rotation (RotatingFileHandler)
- External JSON configuration support

## [2.0.0] - 2026-04-05

### Added
- Expanded subdomain list to 25
- Content analysis with pattern matching for credential harvesting
- Brand impersonation detection

### Removed
- XQL module (not needed in standalone tool)

## [1.0.0] - 2026-04-04

### Added
- Initial release: DNS resolution, crt.sh query, HTTP check
- Baseline comparison with JSON diffing
- Report generation
- Single domain monitoring
