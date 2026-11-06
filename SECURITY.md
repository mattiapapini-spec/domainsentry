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
  authentication** and must sit on an internal network or loopback.

In scope, for example:

- bypassing authentication or RBAC in the authenticated zone;
- reaching internal addresses through the engine despite `SSRF_PROTECTION=true`;
- a domain, page, certificate, WHOIS or DNS answer under an attacker's control that
  crashes or stalls a service, evades detection, or injects content into the dashboard
  (the engine visits lookalike domains by itself, so these inputs are attacker-chosen);
- secrets or client data exposed in logs, responses or stored files.

Out of scope:

- using the unauthenticated engine when it has been exposed to an untrusted network,
  contrary to the documentation (start scans, consume API quotas, occupy workers);
- volumetric denial of service against the host;
- findings that require a malicious operator with shell access to the host.
