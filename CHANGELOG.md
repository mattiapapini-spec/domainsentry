# Changelog

All notable changes to this project will be documented in this file.

## [4.18.2] - 2026-07-07

### Security
- **Security audit of the WHOIS-parsing path (registrant-controlled input).** Since a
  domain's registrant controls its own WHOIS record, the age parser processes
  attacker-controlled data. Audit findings, all fixed:
  - **DoS via huge date list**: a hostile WHOIS returning a giant `creation_date` list
    took ~860ms to parse; now capped at 10 dates (~0.2ms). Date strings are length-bounded.
  - **Log injection**: date values containing newlines could forge log lines. The
    classifier's log statements now pass domain/fuzzer/client through `sanitize_log_input`
    (was imported but unused on those lines); parsed dates are reformatted, so raw
    values never reach output.
  - **Type confusion**: dict/bytes/nested-list/huge-int date values are now safely
    rejected instead of coerced.
  - **Batch DoS**: `/classify/batch` had no size limit; capped at 1000 variants (422 above).
  - 5 security regression tests. 7 real client datasets classify identically (no behavior change).

## [4.18.1] - 2026-07-07

### Fixed
- **Classifier robustness (bug hunt on the v4.18.0 age logic).** Fixed crashes and a
  silent failure found by fuzzing the classifier with malformed/partial input:
  - **WHOIS list-dates**: python-whois frequently returns `creation_date`/`updated_date`
    as a LIST of dates; the age rule silently ignored these (returned age=None), so the
    age classification never fired for those domains. Now takes the earliest date.
  - **Future creation dates**: corrupt/hostile WHOIS with a future date produced a
    negative age; now normalized to unknown.
  - **Additional date formats** parsed (fractional seconds, Z suffix, timezone offsets,
    slash-separated).
  - **None sub-objects** (`dns.records`, `http.checks`, `cert.ct_certificates` set to
    null, or None entries inside the checks list) caused 500 crashes; now handled
    gracefully. These are preexisting issues surfaced by the hunt.
  - 7 regression tests. Verified the 7 real client datasets classify identically to
    v4.18.0 (no behavior change, only crash/robustness fixes).

## [4.18.0] - 2026-07-07

### Improved
- **Classifier now uses domain registration age (the strongest typosquatting signal).**
  Previously the classifier ignored WHOIS creation date and dropped most variants into
  `needs_review`, leaving ~80% of triage to the analyst. It now auto-classifies a domain
  that predates the hostile-registration window (>18 months old) and shows no threat
  signals as `likely_third_party` (LOW), clearing it from the manual queue. Measured on
  7 real client datasets: `needs_review` dropped from 82 to 11 domains, with zero false
  negatives (all known threats stay flagged).
- **Anti-false-negative guards** built into the age rule:
  - An old domain *updated* within the last ~120 days (possible drop-catch / owner
    change) is NOT auto-cleared, it goes to `needs_review` (`old_domain_recently_updated`).
  - A **recent** domain with active MX is no longer auto-cleared as legitimate even if it
    serves a substantial website (facade site + email = typosquat profile), closing a
    false-negative found in testing (a recent look-alike with a decoy page + mail).
- New `likely_third_party` classification (action: whitelist_candidate). 4 regression tests.

## [4.17.0] - 2026-07-04

### Security
- **SSRF protection on outbound fetches.** The engine resolves user-supplied domains and
  refuses requests to internal addresses (cloud metadata 169.254.169.254, loopback,
  RFC1918/private, link-local). Redirects are now followed manually and re-validated at
  each hop, so a public site can't 302 the fetcher into the internal network. Toggle with
  `SSRF_PROTECTION` (default on). Closes an SSRF vector inherent to a tool that fetches
  arbitrary domains. 4 regression tests.
- **Login rate limiting.** Failed logins are throttled per client IP
  (`LOGIN_MAX_FAILURES` / `LOGIN_WINDOW_SEC`, default 5 per 300s) → HTTP 429, to blunt
  brute-force and credential stuffing. Successful login clears the counter. 1 test.

### Notes
- Full internal security audit performed (SQLi, path traversal, auth, secrets, CORS,
  error leakage): SQL is parameterized, file naming is traversal-safe, token/password
  comparison is timing-safe, PBKDF2 is 600k iterations, tokens are stored hashed, and no
  secrets are hardcoded. The two items above were the findings; both are now fixed.

## [4.16.0] - 2026-07-04

### Added
- **Self-service password change for all users.** A "Change password" action in the
  sidebar (available to every role) opens a modal requiring the current password plus
  the new one (confirmed). On success the session is revoked and the user re-logs in.
- **Current-password verification on self-change (backend).** `POST /users/{id}/password`
  now requires the correct current password when a user changes their OWN password
  (a hijacked session can't silently rotate it); an admin resetting someone else's
  password still doesn't need the target's current password. 5 regression tests cover
  the self/admin/wrong-current/cross-user paths.

## [4.15.0] - 2026-07-04

### Added
- **User management in the dashboard (admin).** New "Users" view (visible only with
  `manage_users`): create users (username, password, role viewer/analyst/admin),
  change roles inline, enable/disable accounts, and reset passwords — no more curl
  required to onboard an analyst. The UI prevents self-demotion/self-disable; the
  backend already guarded the case that matters (the last active admin cannot be
  demoted or disabled, and disabling a user revokes their sessions).

## [4.14.0] - 2026-07-04

### Changed
- **Multi-select case-queue filters.** Status, severity and client filters are now
  checkbox dropdowns: select any combination (e.g. "New + In progress", two severities,
  a subset of clients). The client filter is populated dynamically from the case set
  (no more free-text field). Selections combine as AND across the three filters; an
  empty selection means "all". Quick views (New / In progress / Critical) drive the
  same dropdowns. Filtering happens client-side on a single fetch, so combinations
  don't multiply API calls; works together with the group-by-client view.

## [4.13.1] - 2026-07-04

### Fixed
- **Whitelist write failed with a 500 when the whitelist directory was mounted
  read-only.** Both `docker-compose.yml` and `docker-compose.prod.yml` mounted
  `./config/whitelists:/data/feed/whitelists:ro` — the `:ro` made the directory
  read-only, so "Whitelist + close FP" from the dashboard (and any POST to
  `/feed/whitelist`) crashed when trying to write the client's whitelist file.
  Removed `:ro` from both compose files so runtime whitelist additions persist.
- **Graceful error on unwritable whitelist storage.** `/feed/whitelist` now catches
  the write `OSError` and returns a clear **503** ("whitelist storage is not writable
  …") instead of a raw 500, so an operator who intentionally mounts it read-only gets
  an actionable message. Regression test added.

## [4.13.0] - 2026-06-20

### Added
- **Group by client** toggle in the case queue. With many clients onboarded the flat
  list mixes everyone's alerts together; the toggle reorganizes the queue into
  collapsible per-client sections. Each client header shows the case count and a
  per-severity tally (critical/high/medium/low), sections are ordered by highest
  severity then case count, and within a client cases sort by severity then recency.
  Collapsed sections are remembered across refreshes. Client-side only (reuses /cases);
  fetches the full set when grouping so no client is truncated.

## [4.12.0] - 2026-06-19

### Fixed
- **Classifier false positives on legitimate sites (CRITICAL/HIGH on benign domains).**
  Discovered while triaging real client data — the legitimate domain millewin.it (a
  WordPress app with a login area) and dozens of proper-name domains (daniel.com etc.)
  were flagged as "compromise / credential kit". Three root causes fixed:
  1. **Obfuscated-JS detection**: unicode/hex escape sequences ALONE (e.g. wp-emoji's
     many \uXXXX) no longer mark a script as obfuscated. Requires a genuine signal
     (eval/atob/fromCharCode/document.write/unescape/charcode_array) or encoding +
     such a signal.
  2. **External-resource counting**: resources hosted on the page's OWN domain or its
     subdomains (e.g. millewin.it/wp-content/…, download.millewin.it/…) are no longer
     counted as external/third-party. Known CDNs (WordPress.com, fonts, social) also
     excluded. `detect_hidden_elements(html, self_domain=…)` now takes the page domain.
  3. **credential_form_detected**: a login area is normal on the client's legitimate
     domain and on countless third-party sites — it no longer alerts on the legitimate
     domain, and on variants only fires for credential patterns that are NEW vs. the
     baseline (a form appearing where there was none), not for any "login" string.
  - Verified on real data: millewin.it now scores risk 0 (was CRITICAL); a genuine
     phishing kit (obfuscated eval/atob + external exfil server + password form) still
     scores 45 and is fully detected. FPs cleared without introducing false negatives.
  - Regression tests added (4 cases: benign WP emoji, self-hosted resources, real
     obfuscation, real external malicious infra).

## [4.11.0] - 2026-06-19

### Added
- **Reopen closed cases.** A closed case is no longer a dead end: the case drawer now
  shows a "Reopen case" action (gated `manage_cases`) that returns it to in_progress —
  for an FP later found to be a real threat after OSINT, or a mistaken close. Notes can
  also be added to closed cases now (to document the reason for reopening). The backend
  already permitted the transition; only the UI had hidden all actions on closed cases.
  Regression test added (close → reopen).

## [4.10.1] - 2026-06-19

### Fixed
- **dnstwist ran once per target instead of once per distinct legitimate domain.**
  A client with several targets that share the same legitimate (e.g. Kedrion's 3
  targets all map to kedrion.com) triggered the full dnstwist discovery + variant-intel
  pass once per target — 3x the work and 3x the external API calls (WHOIS, crt.sh,
  VirusTotal/OTX) on the identical set of variants. Now dnstwist runs once per DISTINCT
  legitimate domain. Regression test added.

## [4.10.0] - 2026-06-19

### Added
- **Scan progress view** (sidebar → Manage → Scan progress) with a REAL progress bar,
  not an animation. The orchestrator now tracks pipeline telemetry — phase
  (scanning/dnstwist/done), current domain, done/total counts — and exposes it on a new
  `GET /progress` endpoint, which also returns the last 200 pipeline log lines. The view
  polls it every 2.5s and shows a live bar, status, and a log console. Percentage is
  derived from real done/total counts (not estimated).
- **Per-client report download** (buttons on each client card): raw JSON (all collected
  data — feed config, every case, every intel snapshot) and a readable standalone HTML
  report (monitored domains, cases table, per-domain DNS/MX/site/cert signals). Both are
  assembled client-side from existing endpoints; the HTML report carries the standing
  reminder that dnstwist discovery is a signal, not a verdict.

## [4.9.0] - 2026-06-19

### Added
- **Clients view** in the dashboard (sidebar → Manage → Clients). Lists every client as
  a card with its legitimate domain, monitored targets and watchlist (each removable),
  the client note, and the number of open cases. Per-card actions: scan this client,
  add a domain. Fills the gap where clients could be created/edited but not viewed.
- `/summary` now returns `by_client` (open-case count per client) to power the view.

### Fixed
- **Run-scan client dropdown didn't show newly onboarded clients** until a page reload.
  It cached the list on first open; now it reloads the client list every time the panel
  opens (preserving the current selection). Onboard a client → it appears in Run scan
  immediately.

## [4.8.0] - 2026-06-19

### Added
- **Scan scope (all / target / watchlist)** on the pipeline and Run-scan panel.
  `/trigger` accepts `scope`; the pipeline filters feed domains by `type` before
  processing (untyped domains count as target). Lets you scan only targets, only the
  watchlist, or everything.
- **Variant intelligence collection** (opt-in `variant_intel`). When dnstwist discovery
  is on, each *registered* variant (resolves with A or MX) gets the full intel pass
  (DNS/HTTP/cert/WHOIS/reputation) and a persisted snapshot — so discovered variants
  can be triaged tp/fp on real data in the Intelligence tab, instead of only a name and
  a needs_review label. Unregistered permutations are skipped to keep it affordable.
  Surfaced in the Run-scan panel as "Collect full intel on variants" (shown when
  dnstwist is enabled).
  - Rationale: closes the triage gap — previously variants had no snapshot (they skip
    the heavy pipeline), so /intel returned nothing and tp/fp had no evidence base.

## [4.7.1] - 2026-06-19

### Changed
- **Intelligence tab now expands "Hidden risk" into the actual elements**, not just a
  count. Under each HTTP check, "show details" lists the tracking pixels (with src) and
  external resources behind the risk_indicators number, so an analyst can see *what*
  the indicators are and judge them in context (e.g. a parking page's CDN assets are
  noise, not a real threat). All listed URLs are escaped (no XSS from hostile pages).

## [4.7.0] - 2026-06-19

### Added
- **Promote a domain to a monitored target.** Two entry points, both gated on
  `manage_cases`, for moving a dnstwist-discovered variant (or any domain) into
  active monitoring after triage:
  - "Promote to monitored target" button in the case drawer — one click adds the
    case's domain to that client's targets.
  - "Add domain" panel in the sidebar — pick an existing client, enter a domain + type.
  - New `POST /feed/domains/promote` resolves the client's legitimate domain from the
    feed automatically (404 if client unknown, 400 if already monitored). Promoted
    domains are picked up by the next scan with their own baseline diff.
  - Design note: dnstwist variants are NOT auto-promoted (≈74% false positives) —
    triage first, promote only the real ones.

## [4.6.1] - 2026-06-19

### Fixed
- **Case table rendered blank while summary cards showed counts.** The dashboard JS
  was missing declarations for `viewAssignee` and `VIEW_TITLES` (lost during the
  run-scan/onboarding rewrites). `loadCases()` runs at startup and threw
  `ReferenceError: viewAssignee is not defined` before reaching renderRows, so the
  table stayed empty even though /cases returned data and /summary populated the cards.
  Restored both declarations among the global state vars. Added a regression test that
  asserts all state globals used by the load/render path are declared.

## [4.6.0] - 2026-06-19

### Added
- **Client onboarding** in the dashboard (gated on `manage_cases`). New "Onboard client"
  panel: client name, legitimate domain, optional notes, and monitored domains added
  one-by-one or pasted in bulk (target/watchlist per entry), with a staged list before
  submit. On success, offers to run the first scan immediately.
  - New `POST /feed/clients/onboard` endpoint: validates every domain up front, reports
    added vs. skipped (duplicates/invalid), and stores an optional per-client note.
  - `/feed/clients` now returns the client note. Domain names rendered via textContent /
    esc() (no XSS).
  - Scope kept deliberate: monitored-domains + a note, NOT full client CRM (contracts,
    SLAs, contacts) — that belongs in the ticketing/SOAR layer, not the detection tool.

## [4.5.0] - 2026-06-15

### Added
- **"Run scan" button in the dashboard** (gated on `manage_cases`). Opens a panel to
  pick a client (or all clients) and toggle dnstwist, then triggers the pipeline via
  `POST /trigger`. Non-blocking: shows "scan started" and auto-refreshes cases a few
  times while the pipeline runs in the background. Client list populated from
  `/feed/clients`; client names rendered via textContent (no XSS).
- Note: scheduling/automatic runs intentionally NOT included — in an MSSP that is the
  SOAR's responsibility; the tool feeds events to the SOAR rather than self-scheduling.

## [4.4.2] - 2026-06-15

### Fixed
- **Critical: `/diff` crashed (HTTP 500) when a baseline snapshot had a present-but-None
  section** (e.g. `"cert": null` for a domain with no certificates). `dict.get(k, {})`
  returns None for a null value, so `.get()` on it raised AttributeError. Fixed all
  intel sections (dns/http/cert/whois/reputation) and nested fields (spf/dkim/otx/vt)
  in `baseline_diff` to use `(x or {})`. Found in production on the second scan of a
  real Kedrion domain — the diffing path is only exercised when a prior snapshot exists.
  Added regression tests.

## [4.4.1] - 2026-06-15

### Fixed
- Hardened `intel_store._safe()` to reject all-dot names (e.g. a lone `.`) — found
  during security review of the intel persistence layer. Not an escape (stayed
  in-directory) but tightened for correctness.

### Security (documented decision)
- Orchestrator endpoints (`/intel`, `/trigger`, `/status`, `/events`) are internal
  and intentionally unauthenticated. Production deployments MUST isolate them at the
  network layer (production compose with separate containers + reverse proxy exposing
  only the dashboard); they must not be publicly reachable. To be documented in the
  README security/deployment section before publication.

## [4.4.0] - 2026-06-15

### Added
- **Full intelligence persistence + dashboard Intelligence tab.** The pipeline now
  stores, per domain, a full intel snapshot (DNS, certificates, HTTP fingerprint,
  WHOIS, reputation) plus a baseline diff history. Opt-in via `INTEL_STORE=true`.
  - Snapshot overwrites each scan (bounded storage); diff history appends deltas only
  - New `shared/intel_store.py` with path-traversal-safe per-domain files
  - Reuses the classifier's `/diff` engine to compute changes between scans
  - New `GET /intel?client=&domain=` endpoint exposes snapshot + history
  - Dashboard case drawer now has three tabs: Overview / Intelligence / Raw JSON
    - Intelligence: DNS records, subdomains, HTTP fingerprint, certificate list,
      WHOIS, reputation, and baseline diff timeline — with a filter box
    - Raw JSON: full snapshot, copy-to-clipboard

## [4.3.0] - 2026-06-15

### Added
- **Automatic case ingestion** — the orchestrator now pushes every pipeline event
  to the case-manager as a manageable case (opt-in via `CASE_INGEST=true`). This
  closes the loop: scans → events → cases visible in the dashboard, no manual step.
  - Severity derived from classification (phishing→CRITICAL, suspicious→HIGH, etc.)
  - Fail-safe: ingest errors are logged but never break the pipeline
- **Service token** for service-to-service auth (`SERVICE_TOKEN`) — a non-expiring
  static secret mapped to a limited service identity (manage_cases + view only),
  so the orchestrator can authenticate to the case-manager without a user session

## [4.2.2] - 2026-06-15

### Fixed
- Restored orchestrator None-guard (pipeline no longer crashes when a service times
  out) and reduced per-service timeout 120s→45s — regression lost in re-packaging
- Hardened `verify_token_remote` to fail closed on non-JSON responses

## [4.2.1] - 2026-06-14

### Changed
- Dashboard redesign: Elastic-style layout (nav sidebar, saved views), XSIAM dark
  command-center styling with cyberpunk neon accents. Zero external dependencies.

## [4.2.0] - 2026-06-14

### Added
- **SOC Triage Dashboard** (:8013, opt-in) — single-file web UI for case management
  - Login, triage summary cards, filterable case table, slide-out case detail
  - Case detail shows intel, rationale, notes timeline, and audit history
  - Actions gated by permission: assign / self-assign ("Take"), change status,
    add notes, whitelist + close FP — a viewer sees none of them
  - Pure vanilla HTML/CSS/JS, **zero external dependencies** (no CDN, no web fonts)
    so it works on locked-down networks
  - Served by the unified app at `/dashboard` when the case-manager is enabled;
    can be toggled off with `ENABLE_DASHBOARD=false`
- `GET /users/assignable` on the case-manager — minimal id+username list (gated on
  `assign_cases`) so non-admins can populate the assignment dropdown

## [4.1.1] - 2026-06-14

### Added
- **Feed write authentication** (opt-in via `FEED_REQUIRE_AUTH=true`) — POST/DELETE
  endpoints on the feed-manager now require a valid bearer token, validated against
  the case-manager via token introspection (OAuth2-style). Read endpoints stay open.
  - Domain add/remove requires the `manage_cases` permission
  - Whitelist add/remove requires the `whitelist` permission
  - The case-manager forwards the caller's token when proxying whitelist actions,
    so the same permission is enforced end-to-end
  - Disabled by default: the feed-manager remains usable standalone
- `verify_token_remote()` helper in `shared/auth.py` for service-to-service token validation

## [4.1.0] - 2026-06-09

### Added
- **Case Manager service** (:8012, opt-in) — SOC case management with structured auth
  - User management: admin creates users, assigns roles and per-user permissions
  - RBAC: admin/analyst/viewer presets + custom permission overrides
  - Token auth: PBKDF2 passwords (600k iterations), opaque tokens hashed at rest, session revocation
  - Case lifecycle: new → in_progress → closed (TP/FP/benign), assignment, notes, audit history
  - Whitelist action proxies to feed-manager and closes the case as FP
- **Pydantic v1/v2 compatibility shim** (`shared/compat.py`) — runs on either major version

### Changed
- Performance: parallelized intelligence gathering, DNS DKIM/subdomain queries, HTTP fetches
- Connection pooling in orchestrator; non-blocking WHOIS rate limiting; crt.sh size cap

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
