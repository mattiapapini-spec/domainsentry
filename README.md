# DomainSentry

**Self-hosted domain intelligence platform for detecting typosquatting, brand impersonation, and domain compromise.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](docker-compose.yml)

---

DomainSentry discovers lookalike domains via dnstwist permutation, enriches them with DNS/WHOIS/certificate/reputation intelligence, auto-classifies them, and emits structured alerts for SIEM/SOAR integration.

Built for SOC teams and MSSPs. 10 modular services, deployable as a single container or as separate microservices.

## Quick Start

```bash
git clone https://github.com/mattiapapini-spec/domainsentry.git
cd domainsentry
cp .env.example .env
docker compose up -d --build
```

One container, one port, 20 endpoints:

```bash
curl http://localhost:8000/          # endpoint index
curl http://localhost:8000/docs      # Swagger UI
curl "http://localhost:8000/dns?domain=example.com&full=true"
```

## Features

### Intelligence engine
- **Domain permutation discovery** — dnstwist with bitsquatting, homoglyph, transposition, omission, vowel-swap
- **DNS intelligence** — A/AAAA/MX/NS/TXT/SOA/CNAME + DMARC, DKIM (18 selectors), BIMI, CAA, 25 subdomains; every query carries its own status (`ok`, `nodata`, `nxdomain`, `unknown`), and a request stops at a 40 s deadline with the parts not reached marked `unknown`
- **Certificate Transparency** — crt.sh + SAN auto-discovery + TLS live inspection
- **HTTP fingerprinting** — content hashing, credential-form detection, brand keyword matching
- **Hidden element detection** — invisible iframes, hidden forms, obfuscated JS, meta redirects, tracking pixels, base64 payloads, staged code in HTML comments (context-aware: self-hosted resources and benign framework JS are not counted, so legitimate sites don't false-positive)
- **WHOIS intelligence** — structured lookup with registrar, dates, privacy detection, LRU cache
- **Reputation scoring** — VirusTotal + AlienVault OTX + SecurityTrails, queried in parallel within a 40 s deadline, aggregated risk 0-100; the VirusTotal free-tier quota is respected (a domain waits at most 35 s for a slot, then VirusTotal is skipped for that cycle)
- **Auto-classification** — parking, for_sale, legitimate_probable, suspicious, needs_review
- **Baseline diffing** — 40+ alert types (CRITICAL/HIGH/MEDIUM/LOW); a domain flagged as the client's own legitimate is not treated as a threat against itself
- **Failure is not absence** — a collector that fails or does not answer is recorded as failed or undetermined rather than as "no record"; with `INTEL_STORE=true` the previous observation is carried over and marked with the date it was last seen, so an outage does not silently erase what was known

### Triage & operations
- **Analyst dashboard** (opt-in) — single-file web UI: case queue with status/severity/client filters and **group-by-client** view, per-domain intelligence tab (DNS/MX/cert/HTTP with expandable hidden-risk detail + baseline-diff timeline), raw JSON, permission-gated actions
- **Case management** (opt-in) — SQLite-backed triage with token auth, RBAC (admin/analyst/viewer + overrides), assignment, notes, whitelist-and-close, and **reopen**
- **Client management** — onboard clients (single + bulk domains), promote a triaged variant to a monitored target, add domains to existing clients, per-client view with open-case counts and **downloadable reports (raw JSON + readable HTML)**
- **Run scan from the UI** — pick client + scope (all/target/watchlist), optional dnstwist discovery and per-variant intelligence collection
- **Live scan progress** — real pipeline telemetry (phase, current domain, done/total) + streaming log console, via `/progress`
- **NDJSON events + webhook** — structured SOC events for SIEM/SOAR, Slack/Teams notifications

## Deployment Modes

### Unified (default)

Single container, all services on port 8000. Best for evaluation, small deployments, and development.

```bash
docker compose up -d
```

### Production

10 separate containers, each on its own port, independently scalable.

```bash
docker compose -f docker-compose.prod.yml up -d
```

| Service | Port | Responsibility |
|---------|------|---------------|
| feed-manager | 8000 | Domain lists + whitelist |
| dns-intel | 8001 | DNS + DMARC/DKIM/BIMI/CAA |
| cert-intel | 8002 | Certificate Transparency + TLS |
| http-fingerprint | 8003 | Content hash + hidden elements |
| whois-intel | 8004 | WHOIS + cache |
| reputation | 8005 | VT/OTX/ST + risk score |
| dnstwist-engine | 8006 | Permutation scan |
| classifier | 8007 | Auto-classification + diffing |
| orchestrator | 8010 | Pipeline coordination + progress telemetry |
| event-publisher | 8011 | Event routing |
| case-manager | 8012 | Case triage, auth, RBAC (opt-in) |
| dashboard | 8013 | Analyst web UI (opt-in) |

### Local (no Docker)

```bash
SERVICE_HOST=127.0.0.1 PYTHONPATH=. python run_service.py unified    # all services
SERVICE_HOST=127.0.0.1 PYTHONPATH=. python run_service.py dns-intel  # single service
```

`run_service.py` listens on `0.0.0.0` unless `SERVICE_HOST` says otherwise (the container needs
it); outside Docker set `SERVICE_HOST=127.0.0.1`, or the unauthenticated engine is reachable from
your network.

## Security

> **Read this before exposing DomainSentry on any network.**

DomainSentry has two trust zones, and they are secured differently by design.

### Authenticated zone (dashboard + case management)

The **case-manager** and **dashboard** endpoints (`/auth/*`, `/cases/*`, `/users/*`,
`/summary`, and the dashboard UI) require authentication: token-based sessions
(PBKDF2, 600k iterations) with role-based access control (admin / analyst / viewer
plus per-permission overrides). These are safe to expose behind a reverse proxy.

### Unauthenticated zone (intelligence engine) — network isolation required

The **orchestrator** and the individual intelligence services (`/intel`, `/trigger`,
`/status`, `/progress`, `/events`, and the per-service endpoints on ports 8001–8011)
have **no application-level authentication, by design**. They are the internal engine,
intended to sit on a private network and be reachable only by the orchestrator and the
case-manager — not by end users.

The chosen mitigation is **network isolation**, not app-level auth:

- **Production (recommended):** deploy with `docker-compose.prod.yml` (separate
  containers on an internal Docker network). Only `dashboard` and `case-manager` publish
  ports to the host (`ports:`); every orchestrator/intelligence service uses `expose:`
  instead, so it is reachable only from other containers on the internal Docker network,
  never from the host or outside. Put a reverse proxy in front of the published dashboard
  port that forwards only the authenticated paths (`/auth`, `/cases`, `/summary`).
  Example nginx: proxy `location /` and `location /auth`, `location /cases` to the
  dashboard/case-manager; do **not** add a proxy pass for the orchestrator.
- **Unified mode (evaluation only):** everything runs on one port, so the orchestrator
  endpoints ARE reachable by anyone who can reach that port. `docker-compose.yml` binds
  it to `127.0.0.1` by default (`BIND_ADDR` in `.env`, default `127.0.0.1`), so out of
  the box it is reachable only from the host itself — this is fine for `localhost`
  evaluation. If you need it reachable from a LAN or the internet, either switch to the
  production split above, or explicitly set `BIND_ADDR` (e.g. `0.0.0.0`) only once you
  have a path-filtering reverse proxy in front that forwards just the authenticated
  paths.

**Do not** set `BIND_ADDR` to a non-loopback address in unified mode without a
path-filtering reverse proxy in front, and do not port-forward the
orchestrator/intelligence ports in production mode. If you need authenticated
programmatic access to the engine, put it behind the case-manager (which does
authenticate) or add your own gateway.

### Operational notes

- dnstwist discovery is a **signal, not a verdict** (~74% of registered permutations are
  benign third parties or parking). Variants land as `needs_review` cases for manual
  OSINT before any escalation — the tool never auto-promotes a variant to a monitored
  threat.
- API keys (VirusTotal, OTX, SecurityTrails) live in `.env`, which is gitignored. Never
  commit real keys.

### Hardening built in

- **SSRF protection.** The engine fetches user-supplied domains, so every outbound HTTP
  request is validated: the target host is resolved and requests to internal addresses
  (cloud metadata `169.254.169.254`, loopback, RFC1918/private ranges, link-local) are
  refused, and redirects are followed manually so each hop is re-checked (a public site
  can't 302 the fetcher into the internal network). Set `SSRF_PROTECTION=false` only for
  trusted offline labs.
- **Login rate limiting.** Failed logins are throttled per client IP
  (`LOGIN_MAX_FAILURES` in `LOGIN_WINDOW_SEC`, default 5 / 300s) to blunt brute-force and
  credential stuffing. For multi-instance deployments, also front with a WAF/proxy.
- **Password storage.** PBKDF2-HMAC-SHA256, 600k iterations, per-user random salt.
  Session tokens are random and stored hashed, so a database leak exposes neither
  passwords nor usable tokens. Changing your own password requires the current one.
- **Other:** parameterized SQL throughout, path-traversal-safe file naming, timing-safe
  token/password comparison, security headers on every response, and a request-size limit.

### Operating limits

Know these before running DomainSentry in production:

- **Keep the engine unreachable from untrusted networks.** Anyone who can reach the
  unauthenticated zone can start scans, spend your VirusTotal, OTX and SecurityTrails
  quotas, and occupy worker capacity. Network isolation is the control (see above).
- **Unified mode shares one worker pool** between the engine, the dashboard and login.
  Heavy or slow engine traffic can delay the dashboard. For multi-analyst use, prefer the
  production split, where each service has its own process.
- **Collector deadlines.** `/dns` and `/reputation` answer within 40 s, marking what they
  could not reach as undetermined; the orchestrator waits `SERVICE_TIMEOUT` (default 45 s),
  which must stay above 40.
- **VirusTotal free tier.** With 4 calls per minute, a domain waits at most 35 s for a quota
  slot; if none frees up, VirusTotal is skipped for that cycle (with `INTEL_STORE=true` its
  previous result is carried over). A provider call still running at the deadline finishes
  on its own thread after the response.
- **Python version.** Run on the Python of the provided image (3.12). The HTML parsing
  hardening checks the standard library's internals at startup; if they differ it keeps
  the standard code paths and logs a warning, so check the startup log after changing
  the Python version.
- **Discovery is a signal.** dnstwist variants are for an analyst to review (as cases with
  `CASE_INGEST=true`), classified on their own data when variant intelligence collection is
  enabled; none is promoted to a monitored target automatically.

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │         UNIFIED MODE (:8000)            │
                    │   All services in one container          │
                    └─────────────────────────────────────────┘
                                     OR
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ DNS :8001│   │CERT :8002│   │HTTP :8003│   │WHOIS:8004│   │ REP :8005│
└─────┬────┘   └─────┬────┘   └─────┬────┘   └─────┬────┘   └─────┬────┘
      └───────────────┴───────┬───────┴───────────────┴───────────────┘
                       ┌───────┴───────┐   ┌─────────────┐
                       │ dnstwist :8006│   │ Classifier  │
                       └───────┬───────┘   │    :8007    │
                               └─────┬─────┘
        ── INTERNAL NETWORK ─────────┼──────────────────────────────
    ┌──────────┐              ┌──────┴──────┐              ┌──────────┐
    │  Feed    │──────────────│ Orchestrator│──────────────│  Events  │
    │  :8000   │              │    :8010    │              │  :8011   │
    └──────────┘              └──────┬──────┘              └────┬─────┘
                                     │ intel + cases            │
        ── AUTHENTICATED EDGE ───────┼──────────────────────────┼─────
                              ┌──────┴──────┐            ┌───────┴──────┐
                              │ Case-mgr    │            │ [SIEM/SOAR]  │
                              │   :8012     │            │  [Webhook]   │
                              └──────┬──────┘            └──────────────┘
                              ┌──────┴──────┐
                              │ Dashboard   │  ◄── users log in here
                              │   :8013     │
                              └─────────────┘
```

The dashed lines mark the trust boundary (see [Security](#security)): the intelligence
engine and orchestrator sit on the internal network; only the case-manager and dashboard
are meant to be reachable by users, and both authenticate.

## Usage

All examples use unified mode (port 8000). For production mode, replace with the service port from the table above.

### Enrich a domain

```bash
# DNS intelligence
curl "http://localhost:8000/dns?domain=example.com&full=true&subdomains=true"

# Certificate Transparency
curl "http://localhost:8000/cert?domain=example.com&tls_live=true"

# HTTP fingerprint + hidden element detection
curl "http://localhost:8000/http?domain=example.com"

# WHOIS
curl "http://localhost:8000/whois?domain=example.com"

# Reputation (requires API keys in .env)
curl "http://localhost:8000/reputation?domain=example.com"

# Permutation scan (slow, 30-120s)
curl "http://localhost:8000/twist?domain=example.com"
```

### Auto-classify a variant

```bash
curl -X POST "http://localhost:8000/classify/variant" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "examp1e.com",
    "fuzzer": "homoglyph",
    "dns": {"records": {"A": ["1.2.3.4"], "MX": []}},
    "http": {"checks": [{"status_code": 200, "content_length": 95}], "overall_status": "active"}
  }'
```

```json
{
  "domain": "examp1e.com",
  "auto_classification": "parking",
  "confidence": "high",
  "rule": "http_active_minimal_content",
  "rationale": "HTTP active with minimal content (<200b), typical of parking/redirect pages",
  "action": "monitor_passive",
  "manual_review_required": false
}
```

### Manage monitored domains

```bash
# Add domain to feed
curl -X POST "http://localhost:8000/feed/domains" \
  -H "Content-Type: application/json" \
  -d '{"domain": "evil-example.com", "client": "acme", "legitimate": "example.com", "type": "target"}'

# Whitelist a verified domain
curl -X POST "http://localhost:8000/feed/whitelist?client=acme" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example-corp.com", "reason": "Verified independent business"}'

# Trigger monitoring pipeline
curl -X POST "http://localhost:8000/trigger" \
  -H "Content-Type: application/json" \
  -d '{"client": "acme", "include_dnstwist": true}'
```

### Whitelist via text file

Create `config/whitelists/acme.txt`:
```
# Whitelist verified domains — acme
# Format: domain | reason | date
example-corp.com | Verified independent business | 2026-01-15
similar-name.com | Confirmed via OSINT, unrelated | 2026-01-15
```

Mounted read-only in Docker, the feed manager reads it automatically.

## API Reference

All endpoints available on port 8000 (unified) or individual ports (production).

### Intelligence

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dns?domain=&full=true&subdomains=true` | DNS + DMARC/DKIM/BIMI/CAA + subdomains |
| GET | `/cert?domain=&tls_live=true` | Certificate Transparency + TLS |
| GET | `/http?domain=&detect_hidden=true` | HTTP fingerprint + hidden elements |
| GET | `/whois?domain=` | WHOIS structured lookup |
| GET | `/reputation?domain=&sources=vt,otx,st` | Multi-source reputation + risk score |
| GET | `/twist?domain=&registered_only=true` | dnstwist permutation scan |

### Classification

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/classify/variant` | Auto-classify a single variant |
| POST | `/classify/batch` | Batch classification |
| POST | `/diff` | Baseline diff with alert generation |

### Feed & Whitelist

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/feed/domains?client=` | List monitored domains |
| POST | `/feed/domains` | Add domain |
| DELETE | `/feed/domains/{domain}` | Remove domain |
| GET | `/feed/whitelist?client=` | List whitelist |
| POST | `/feed/whitelist?client=` | Whitelist a domain |
| DELETE | `/feed/whitelist/{domain}?client=` | Remove from whitelist |
| GET | `/feed/clients` | List clients (derived from feed) |

### Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Service index |
| GET | `/health` | Health check |
| GET | `/status` | All services health (prod mode) |
| POST | `/trigger` | Trigger pipeline run |
| GET | `/events?client=&last=50` | Read SOC events |
| POST | `/publish` | Publish events |
| GET | `/docs` | Swagger UI (auto-generated) |

## Classification Rules

| Category | Signals | Action |
|----------|---------|--------|
| **parking** | HTTP 200 <200 bytes, known parking NS/IPs | Monitor passively |
| **for_sale** | Marketplace NS (BrandBucket, etc.), parking MX | Monitor passively |
| **suspicious** | Hidden elements risk ≥30, MX without A record, privacy email, email forwarding | Block + active monitor |
| **legitimate_probable** | Enterprise certs, substantial content >3KB | Whitelist candidate |
| **needs_review** | No rule matches with confidence | Manual OSINT review |

Hidden elements with risk ≥30 override content-based classification: a site with 50KB of content but a hidden phishing form is classified as suspicious, not legitimate.

## Hidden Element Detection

10 categories of hidden content, each contributing to a risk score (0-100):

| Category | Risk | Indicators |
|----------|------|------------|
| Hidden forms | +30 | `display:none`, `visibility:hidden`, `opacity:0` on `<form>` |
| Invisible iframes | +25 | 0/1px dimensions, CSS hidden, offscreen positioning |
| Obfuscated JS | +20 | `eval()`, `atob()`, `String.fromCharCode`, hex/unicode encoding |
| Meta redirects | +20 | `<meta http-equiv="refresh">` with external URL |
| Hidden divs with forms | +25 | Hidden `<div>` containing `<form>` or `<input>` |
| Hidden inputs (>3) | +15 | Multiple `<input type="hidden">` fields |
| Base64 payloads | +15 | Large inline base64 content |
| Staged code in comments | +15 | HTML/JS inside `<!-- -->` comments |
| Tracking pixels | +10 | 1x1 `<img>` elements |
| External resources | logged | Non-CDN external URLs in src/href/action |

On a **legitimate domain** (the client's own), any hidden element detection triggers CRITICAL alerts with compromise prefix.

## Configuration

All settings come from environment variables; copy `.env.example` to `.env` and edit it.
`.env` is gitignored: never commit real keys. With Docker Compose, a variable reaches the
container only if the compose file lists it under `environment:`; to set one that is not listed
(for example `WHOIS_ONLY_DOMAINS`, `SERVICE_TIMEOUT`, `SSRF_PROTECTION`, `LOGIN_*`, `VT_RATE_*`),
add it there in the interpolated form (`- NAME=${NAME:-}`) and keep the value in `.env`: never
write client domains or secrets into a compose file. A few values are written literally in the
compose files (for example `TOKEN_TTL_HOURS=12`, and `TARGET_WEBHOOK_ENABLED: "false"` in
`docker-compose.prod.yml`) and do not follow `.env` until you change them there.

| Variable | Default | Description |
|----------|---------|-------------|
| `BIND_ADDR` | `127.0.0.1` | Host address the unified container publishes on (see [Security](#security)) |
| `VT_API_KEY` | | VirusTotal API key (free tier: 4 requests/min) |
| `OTX_API_KEY` | | AlienVault OTX API key |
| `ST_API_KEY` | | SecurityTrails API key (free tier: 50 requests/month) |
| `VT_RATE_LIMIT` / `VT_RATE_WINDOW` | 4 / 60 | VirusTotal quota: calls per window (seconds) |
| `WEBHOOK_URL` / `TARGET_WEBHOOK_ENABLED` | / `false` | Slack/Teams webhook URL; notifications are sent only with `TARGET_WEBHOOK_ENABLED=true` |
| `ENABLE_CASE_MANAGER` | `false` | Enable case management, authentication and RBAC |
| `ENABLE_DASHBOARD` | `true` | Serve the analyst dashboard alongside the case-manager (only when `ENABLE_CASE_MANAGER=true`) |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / random | First admin account; an empty password is generated and logged once at startup |
| `TOKEN_TTL_HOURS` | 12 | Session token lifetime |
| `LOGIN_MAX_FAILURES` / `LOGIN_WINDOW_SEC` | 5 / 300 | Failed logins allowed per client IP in the window |
| `FEED_REQUIRE_AUTH` | `false` | Require a valid token on feed write endpoints (needs the case-manager) |
| `CASE_INGEST` / `SERVICE_TOKEN` | `false` / | Turn every pipeline event into a case; the token is a long random service-to-service secret (`openssl rand -hex 32`) |
| `INTEL_STORE` | `false` | Persist per-domain intelligence snapshots and baseline-diff history (dashboard Intelligence tab) |
| `WHOIS_ONLY_DOMAINS` | | Comma-separated lookalikes for which a WHOIS-only collection is attempted even when they do not resolve |
| `SSRF_PROTECTION` | `true` | Refuse outbound requests to internal addresses; keep `true` outside offline labs |
| `SERVICE_TIMEOUT` | 45 | How long the orchestrator waits for a service; **must stay above 40** (the DNS and reputation deadlines) |
| `DNS_TIMEOUT` | 10 | Per-query DNS timeout (seconds) |
| `HTTP_TIMEOUT` | 15 | HTTP request timeout |
| `CRTSH_TIMEOUT` | 30 | crt.sh query timeout |
| `WHOIS_DELAY` / `WHOIS_TIMEOUT` | 2 / 10 | Spacing between WHOIS queries, and per-lookup timeout |
| `CACHE_TTL` | 86400 | WHOIS cache TTL (seconds) |
| `DNSTWIST_NAMESERVERS` / `DNSTWIST_TIMEOUT` | `8.8.8.8,1.1.1.1` / 300 | Resolvers and time budget of the permutation scan |
| `PIPELINE_MAX_DURATION` | 7200 | Max pipeline run before a stale run is reset |
| `PORT` | 8000 | Unified mode port (host side, Docker Compose) |
| `SERVICE_HOST` | `0.0.0.0` | Listen address of `run_service.py`; the container needs `0.0.0.0`, outside Docker use `127.0.0.1` |

All API keys are optional: a source without a key is not queried, and the rest of the
pipeline runs without it.

## SOAR Integration

Complements the native [dnstwist XSOAR pack](https://cortex.marketplace.pan.dev/marketplace/details/dnstwist/). Use dnstwist for discovery, DomainSentry for continuous monitoring and classification.

```
Playbook: Domain Intelligence Enrichment
  Step 1: !dnstwist domain=${domain}                    ← native XSOAR pack
  Step 2: GET http://domainsentry:8000/dns?domain=${domain}&full=true
  Step 3: GET http://domainsentry:8000/reputation?domain=${domain}
  Step 4: POST http://domainsentry:8000/classify/variant body=${aggregated}
  Step 5: Populate War Room
```

Zabbix integration: external check triggers `POST /trigger`, trapper items receive risk scores.

## Development

```bash
# Unified (all services), loopback only
SERVICE_HOST=127.0.0.1 PYTHONPATH=. python run_service.py unified

# Single service
SERVICE_HOST=127.0.0.1 PYTHONPATH=. python run_service.py dns-intel

# Dependencies, plus pinned dev tools (pytest, httpx, ruff)
pip install -r requirements.txt -r requirements-dev.txt

# Lint (rules are in pyproject.toml; the gate is zero violations)
ruff check .
```

### Tests

The suite has about 4,200 tests and never touches the network: DNS, WHOIS and HTTP are
replaced by fakes, and state goes to temporary paths.

```bash
# Parallel driver (Python 3.11+, Linux): splits the suite over N processes, each with its
# own state directories, and fails if any collected test is not run exactly once
PATH=/path/to/node/bin:$PATH python3 tests/run_parallel.py -n 4

# Serial run (what CI does: it also proves no test depends on the order)
PYTHONPATH=. pytest tests/ -q
```

- **Node.js** is needed by the dashboard rendering tests, which run the page's real script.
  Without `node` on the `PATH` those tests are skipped; with `DOMAINSENTRY_REQUIRE_NODE=1`
  (set in CI) a missing `node` fails the run instead.
- A few test modules use fixed paths under `/tmp` (`/tmp/cm_svc.db`, `/tmp/test_feed_*`).
  Delete them before a run when switching between checkouts, and never run two suites at
  the same time.
- Stop the parallel driver with Ctrl-C or SIGTERM, never SIGKILL: its workers run in their
  own process groups.
- Contributions follow the project's rule: a failing regression test first, then the
  smallest fix that makes it pass, and a `CHANGELOG.md` entry that says what failed, why,
  and what changed in numbers (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Roadmap

- [ ] Async orchestrator with `httpx` (parallel intelligence gathering)
- [ ] Authentication on the intelligence engine (today it relies on network isolation)
- [ ] Per-process capacity limits for the unauthenticated endpoints in unified mode
- [ ] Prometheus metrics (`/metrics`)
- [ ] Request ID tracing across services
- [ ] Pagination on list endpoints
- [ ] NRD (Newly Registered Domains) feed integration
- [ ] Passive DNS historical lookups
- [ ] Content similarity scoring (ssdeep/TLSH)
- [ ] Kubernetes Helm chart

## License

[MIT](LICENSE)
