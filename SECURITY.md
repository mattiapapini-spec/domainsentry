# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue, pull request or discussion
for a suspected vulnerability.

A useful report includes:

- the affected component (service, endpoint or file) and the version or commit;
- the deployment mode (unified or production split) and relevant settings;
- steps to reproduce, or a proof of concept that uses `example.com`-style domains and
  documentation IP ranges (RFC 5737), never third-party systems you do not own;
- the impact you expect.

Reports are handled on a best-effort basis. You will get an acknowledgement in the
advisory thread, and the fix will be credited to you in `CHANGELOG.md` unless you ask
otherwise. Please give a reasonable time for a fix before any public disclosure.

## Supported versions

Only the latest state of the default branch receives security fixes.

## Scope and trust model

DomainSentry has two trust zones by design (see [README § Security](README.md#security)):

- the **authenticated zone** (dashboard and case management) requires authentication for everything
  except login, the health check and the static dashboard page;
- the **intelligence engine** (orchestrator and collectors) has **no application-level
  authentication**, with two exceptions below, and must sit on an internal network or loopback.

Two engine endpoints are authenticated because they start work or spend quota:

- `POST /trigger` and `POST /trigger/reset` accept `Authorization: Bearer <PIPELINE_TOKEN>`, or
  the session of a case-manager user with `manage_cases` (the `service` role is refused).
  Failure is closed: no credential, an unreachable case-manager or a malformed answer gives
  401 or 403, never access.
- `GET /reputation` requires the same Bearer when `PIPELINE_TOKEN` is set; without a token it
  is open and logs a warning at startup.

About `PIPELINE_TOKEN`:

- generate it with `openssl rand -hex 32` (shorter than 32 characters logs a warning);
- keep it separate from `SERVICE_TOKEN`, the case-manager's service identity: do not reuse it;
- rotate it by changing `.env` and restarting orchestrator and reputation;
- a value of only spaces is a misconfiguration: `/reputation` refuses everyone (fail-closed);
  an empty value means `/reputation` open and `/trigger` open only to sessions.

Session checks on `/trigger` are limited to `AUTH_REMOTE_MAX_CONCURRENT` (default 4) in flight.
Residual risk: under a flow of fake tokens from an anonymous client the slots fill, and user
sessions get 503 on `/trigger` and `/trigger/reset` until it stops; `PIPELINE_TOKEN` and
`/health` are not affected. Mitigate with a per-IP rate limit on the reverse proxy. A Bearer
that is not the `PIPELINE_TOKEN` is forwarded to the case-manager as a candidate session token.
`/intel`, `/status`, `/progress`, `/publish`, the `/feed/*` writes (unless `FEED_REQUIRE_AUTH=true`)
and the collector ports stay unauthenticated.

In scope, for example:

- bypassing authentication or RBAC in the authenticated zone;
- reaching internal addresses through the engine despite `SSRF_PROTECTION=true`;
- a domain, page, certificate, WHOIS or DNS answer under an attacker's control that
  crashes or stalls a service, evades detection, or injects content into the dashboard
  (the engine visits lookalike domains by itself, so these inputs are attacker-chosen);
- secrets or client data exposed in logs, responses or stored files.

Out of scope:

- using the unauthenticated parts of the engine when it has been exposed to an untrusted
  network, contrary to the documentation (read intelligence, publish events, occupy workers);
- the 503 on `/trigger` sessions under an anonymous flood of fake tokens, accepted and
  documented above;
- volumetric denial of service against the host;
- findings that require a malicious operator with shell access to the host.
