#!/usr/bin/env python3
"""
Service Runner — avvia il microservizio selezionato via SERVICE_NAME.
Un'immagine Docker, N container, ciascuno con un SERVICE_NAME diverso.
"""

import os
import sys
import uvicorn

SERVICE_MAP = {
    "unified":          ("unified",                   8000),
    "feed-manager":     ("services.feed_manager",     8000),
    "dns-intel":        ("services.dns_intel",        8001),
    "cert-intel":       ("services.cert_intel",       8002),
    "http-fingerprint": ("services.http_fingerprint", 8003),
    "whois-intel":      ("services.whois_intel",      8004),
    "reputation":       ("services.reputation",       8005),
    "dnstwist-engine":  ("services.dnstwist_engine",  8006),
    "classifier":       ("services.classifier",       8007),
    "orchestrator":     ("services.orchestrator",     8010),
    "event-publisher":  ("services.event_publisher",  8011),
    "case-manager":     ("services.case_manager",     8012),
    "dashboard":        ("services.dashboard",        8013),
}

def main():
    service = os.environ.get("SERVICE_NAME", sys.argv[1] if len(sys.argv) > 1 else "")

    if service not in SERVICE_MAP:
        print(f"Servizio '{service}' non trovato.")
        print(f"Servizi disponibili: {', '.join(sorted(SERVICE_MAP.keys()))}")
        sys.exit(1)

    module, default_port = SERVICE_MAP[service]
    port = int(os.environ.get("SERVICE_PORT", str(default_port)))
    host = os.environ.get("SERVICE_HOST", "0.0.0.0")
    workers = int(os.environ.get("SERVICE_WORKERS", "1"))

    print(f"╔══════════════════════════════════════════════╗")
    print(f"║  Domain Intelligence Platform v4.0           ║")
    print(f"║  Service: {service:<35}║")
    print(f"║  Listening: {host}:{port:<28}║")
    print(f"╚══════════════════════════════════════════════╝")

    uvicorn.run(
        f"{module}:app",
        host=host,
        port=port,
        workers=workers,
        log_level="info",
    )


if __name__ == "__main__":
    main()
