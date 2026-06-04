"""
Dnstwist Engine Service (:8006)
Modulo 7 estratto — Permutation scan via dnstwist.
Usa subprocess con --format json per compatibilità con tutte le versioni.
"""

import os, logging, time, json, subprocess
from fastapi import FastAPI, APIRouter, Query
from fastapi.responses import JSONResponse
from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.utils import now_iso

app = FastAPI(title="Dnstwist Engine", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("dnstwist")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [TWIST] %(message)s")

DNSTWIST_TIMEOUT = int(os.environ.get("DNSTWIST_TIMEOUT", "300"))
NAMESERVERS = os.environ.get("DNSTWIST_NAMESERVERS", "8.8.8.8,1.1.1.1")


@app.get("/health")
def health():
    try:
        proc = subprocess.run(["dnstwist", "--version"], capture_output=True, text=True, timeout=5)
        version = proc.stdout.strip() or proc.stderr.strip()
        available = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        version = "not found"
        available = False
    return {"status": "healthy" if available else "degraded",
            "service": "dnstwist-engine", "version": "4.0.0",
            "dnstwist_version": version}


@router.get("/twist", tags=["Permutation Scan"])
def twist_check(
    domain: str = Query(..., description="Dominio legittimo da analizzare",
                        min_length=4, max_length=253, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"),
    registered_only: bool = Query(True, description="Solo varianti con DNS attivo")
):
    logger.info(f"Scan: {sanitize_log_input(domain)} registered_only={registered_only}")
    start = time.time()

    cmd = ["dnstwist", "--format", "json", "--nameservers", NAMESERVERS]
    if registered_only:
        cmd.append("--registered")
    cmd.append(domain)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=DNSTWIST_TIMEOUT)
        if proc.returncode != 0:
            return JSONResponse(status_code=500,
                                content={"error": f"dnstwist exit {proc.returncode}: {proc.stderr[:500]}"})

        results = json.loads(proc.stdout) if proc.stdout.strip() else []

        variants = []
        total_perms = 0
        for item in results:
            if item.get("fuzzer") == "original" or item.get("fuzzer", "").startswith("*"):
                continue
            total_perms += 1
            variants.append({
                "domain": item.get("domain", ""),
                "fuzzer": item.get("fuzzer", ""),
                "dns_a": item.get("dns_a", []) if isinstance(item.get("dns_a"), list) else [item["dns_a"]] if item.get("dns_a") else [],
                "dns_aaaa": item.get("dns_aaaa", []) if isinstance(item.get("dns_aaaa"), list) else [item["dns_aaaa"]] if item.get("dns_aaaa") else [],
                "dns_mx": item.get("dns_mx", []) if isinstance(item.get("dns_mx"), list) else [item["dns_mx"]] if item.get("dns_mx") else [],
                "dns_ns": item.get("dns_ns", []) if isinstance(item.get("dns_ns"), list) else [item["dns_ns"]] if item.get("dns_ns") else [],
                "geoip": item.get("geoip", ""),
            })

        elapsed = round(time.time() - start, 2)
        logger.info(f"Completato: {sanitize_log_input(domain)} — {len(variants)} varianti in {elapsed}s")

        return JSONResponse(content={
            "domain": domain, "timestamp": now_iso(),
            "total_permutations": total_perms,
            "registered_variants": len(variants),
            "variants": variants,
            "execution_time_seconds": elapsed,
            "error": None
        })
    except subprocess.TimeoutExpired:
        return JSONResponse(status_code=504,
                            content={"error": f"Timeout dopo {DNSTWIST_TIMEOUT}s"})
    except json.JSONDecodeError as e:
        return JSONResponse(status_code=500,
                            content={"error": f"JSON parse error: {e}"})
    except FileNotFoundError:
        return JSONResponse(status_code=503,
                            content={"error": "dnstwist binary non trovato"})

app.include_router(router)
