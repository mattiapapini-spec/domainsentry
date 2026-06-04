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

- **Domain permutation discovery** — dnstwist with bitsquatting, homoglyph, transposition, omission, vowel-swap
- **DNS intelligence** — A/AAAA/MX/NS/TXT/SOA/CNAME + DMARC, DKIM (17 selectors), BIMI, CAA, 25 subdomains
- **Certificate Transparency** — crt.sh + SAN auto-discovery + TLS live inspection
- **HTTP fingerprinting** — Content hashing, phishing form detection, brand keyword matching
- **Hidden element detection** — Invisible iframes, hidden forms, obfuscated JS, meta redirects, tracking pixels, base64 payloads, staged code in HTML comments (10 categories, risk score 0-100)
- **WHOIS intelligence** — Structured lookup with registrar, dates, privacy detection, LRU cache
- **Reputation scoring** — VirusTotal + AlienVault OTX + SecurityTrails, aggregated risk 0-100
- **Auto-classification** — parking, for_sale, legitimate_probable, suspicious, needs_review
- **Legitimate domain compromise detection** — Hidden elements on your own domain trigger CRITICAL alerts
- **Baseline diffing** — 40+ alert types (CRITICAL/HIGH/MEDIUM/LOW)
- **Whitelist** — Exclude verified domains via API or plain text files
- **NDJSON events** — Structured SOC events for SIEM/SOAR
- **Webhook** — Slack/Teams notifications

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
| orchestrator | 8010 | Pipeline coordination |
| event-publisher | 8011 | Event routing |

### Local (no Docker)

```bash
PYTHONPATH=. python run_service.py unified            # all services
PYTHONPATH=. python run_service.py dns-intel           # single service
```

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │         UNIFIED MODE (:8000)            │
                    │      All services, one container        │
                    └─────────────────────────────────────────┘
                                     OR
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ DNS :8001│   │CERT :8002│   │HTTP :8003│   │WHOIS:8004│   │ REP :8005│
└─────┬────┘   └─────┬────┘   └─────┬────┘   └─────┬────┘   └─────┬────┘
      └───────────────┴───────────────┴───────────────┴───────────────┘
                                     │
                              ┌──────┴──────┐
                              │ Classifier  │
                              │    :8007    │
                              └──────┬──────┘
                                     │
    ┌──────────┐              ┌──────┴──────┐              ┌──────────┐
    │  Feed    │──────────────│ Orchestrator│──────────────│  Events  │
    │  :8000   │              │    :8010    │              │  :8011   │
    └──────────┘              └─────────────┘              └────┬─────┘
                                                               │
                                                    ┌──────────┼──────────┐
                                                    ▼          ▼          ▼
                                                 [File]   [Webhook]  [SIEM/SOAR]
```

Every service works standalone. In unified mode all endpoints share port 8000.

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
