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
git clone https://github.com/YOUR_USERNAME/domainsentry.git
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
- **DNS intelligence** — A/AAAA/MX/NS/TXT/SOA/CNAME + DMARC, DKIM (17 selectors), BIMI, CAA, 25 subdomains
- **Certificate Transparency** — crt.sh + SAN auto-discovery + TLS live inspection
- **HTTP fingerprinting** — content hashing, credential-form detection, brand keyword matching
- **Hidden element detection** — invisible iframes, hidden forms, obfuscated JS, meta redirects, tracking pixels, base64 payloads, staged code in HTML comments (context-aware: self-hosted resources and benign framework JS are not counted, so legitimate sites don't false-positive)
- **WHOIS intelligence** — structured lookup with registrar, dates, privacy detection, LRU cache
- **Reputation scoring** — VirusTotal + AlienVault OTX + SecurityTrails, aggregated risk 0-100
- **Auto-classification** — parking, for_sale, legitimate_probable, suspicious, needs_review
- **Baseline diffing** — 40+ alert types (CRITICAL/HIGH/MEDIUM/LOW); a domain flagged as the client's own legitimate is not treated as a threat against itself

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
PYTHONPATH=. python run_service.py unified            # all services
PYTHONPATH=. python run_service.py dns-intel           # single service
```

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
  containers on an internal Docker network) behind a reverse proxy that exposes **only**
  the dashboard port and the authenticated paths (`/auth`, `/cases`, `/summary`). The
  orchestrator and intelligence services stay on the internal network, unreachable from
  outside. Example nginx: proxy `location /` and `location /auth`, `location /cases` to
  the dashboard/case-manager; do **not** add a proxy pass for the orchestrator.
- **Unified mode (evaluation only):** everything runs on port 8000, so the orchestrator
  endpoints ARE reachable by anyone who can reach that port. This is fine on `localhost`
  or a trusted LAN for evaluation, but for any exposed deployment you must either use the
  production split above, or put a path-filtering reverse proxy in front that only
  forwards the authenticated paths.

**Do not** expose unified mode directly to the internet, and do not port-forward the
orchestrator/intelligence ports. If you need authenticated programmatic access to the
engine, put it behind the case-manager (which does authenticate) or add your own gateway.

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

| Variable | Default | Description |
|----------|---------|-------------|
| `VT_API_KEY` | | VirusTotal API key (free: 4 req/min) |
| `OTX_API_KEY` | | AlienVault OTX API key |
| `ST_API_KEY` | | SecurityTrails API key (free: 50 req/month) |
| `WEBHOOK_URL` | | Slack/Teams webhook URL |
| `DNS_TIMEOUT` | 10 | DNS query timeout (seconds) |
| `HTTP_TIMEOUT` | 15 | HTTP request timeout |
| `CRTSH_TIMEOUT` | 30 | crt.sh query timeout |
| `WHOIS_DELAY` | 2 | Delay between WHOIS queries |
| `CACHE_TTL` | 86400 | WHOIS cache TTL (seconds) |
| `PIPELINE_MAX_DURATION` | 7200 | Max pipeline run before stale reset |
| `PORT` | 8000 | Unified mode port |

All API keys are optional — services degrade gracefully when missing.

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
# Unified (all services)
PYTHONPATH=. python run_service.py unified

# Single service
PYTHONPATH=. python run_service.py dns-intel

# Tests
pip install pytest
PYTHONPATH=. pytest tests/ -v

# Lint
pip install ruff
ruff check .
```

## Roadmap

- [ ] Async orchestrator with `httpx` (parallel intelligence gathering)
- [ ] API authentication (API key header)
- [ ] Rate limiting on endpoints
- [ ] Prometheus metrics (`/metrics`)
- [ ] Request ID tracing across services
- [ ] Pagination on list endpoints
- [ ] NRD (Newly Registered Domains) feed integration
- [ ] Passive DNS historical lookups
- [ ] Content similarity scoring (ssdeep/TLSH)
- [ ] Kubernetes Helm chart

## License

[MIT](LICENSE)
