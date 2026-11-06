"""
HTTP Fingerprint Service (:8003)
Modulo 5 estratto — Content hash, form detection, brand impersonation.
"""

import os, logging, re, threading, contextlib, time
from fastapi import FastAPI, APIRouter, Query
from fastapi.responses import JSONResponse

from shared.security import apply_security, sanitize_log_input
from shared.utils import (http_get_with_retry, normalize_html_for_fingerprint,
                           extract_visible_text, detect_suspicious_patterns,
                           detect_hidden_elements, extract_title, content_hash, now_iso)
from shared.constants import DEFAULT_SUSPICIOUS_PATTERNS

app = FastAPI(title="HTTP Fingerprint", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("http-fp")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [HTTP] %(message)s")

HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "15"))
# SEC-47/SEC-48: body analysis is CPU-bound and holds the GIL. Bodies analysed side by side, across every /http
# request, only queue their long calls behind each other, and the rest of the process with them: so one body is
# analysed at a time in the whole process, however long the others wait. Among waiting bodies the shortest goes
# first (ties: arrival order), so a page of normal size passes hostile ones while no waiting body has aged; a body
# that has waited more than ANALYSIS_AGING_S (read at every hand-over) goes before every body that arrived after it,
# so no body waits for ever. The price of that bound: under sustained load from many concurrent callers the queue
# ages and is served in arrival order, and a page of normal size waits for the whole backlog ahead of it. Two bodies
# of one request are never analysed together: while one is in analysis its siblings cannot take the turn.
ANALYSIS_AGING_S = 10
# Safety valve: an analysis lasts seconds, so a turn held for more than ANALYSIS_STUCK_S was lost to a defect and
# would stop every later analysis. Waiting bodies check every ANALYSIS_STUCK_POLL_S real seconds (both read at every
# check) and, if a body may take the turn, give it to the one the usual order designates and log it; the stuck body,
# if it ever ends, has no turn left to pass on. Limit: a body given the turn whose thread stays suspended for more
# than ANALYSIS_STUCK_S is passed by the valve, and then may analyse beside whichever body holds the turn after it,
# never beside a body of its own request.
ANALYSIS_STUCK_S = 60
ANALYSIS_STUCK_POLL_S = 1.0
# The clock of aging and of the safety valve, read at every use.
_turn_clock = time.monotonic


class _Ticket(threading.Event):
    """A body's place in the queue, set when the turn is given to it; the holder of the turn is its ticket."""

    def __init__(self, size, since, request):
        super().__init__()
        self.size, self.since, self.request = size, since, request


class _AnalysisTurn:
    """One body analysis at a time in the whole process: shortest body first, with aging and a safety valve, and
    never two bodies of one request."""

    def __init__(self):
        self._lock = threading.Lock()
        self._holder = None   # the ticket holding the turn, None when the turn is free
        self._since = 0.0     # _turn_clock() when the holder was given the turn
        self._waiting = []    # tickets of the waiting bodies, in arrival order
        # Requests with a body in analysis, from the hand-over to its end, also after the safety valve gave its turn
        # away: a sibling given the turn would analyse beside it, or wait for it while holding up every other request.
        self._analysing = set()

    @contextlib.contextmanager
    def take(self, size, request):
        ticket = self._wait_for_turn(size, request)
        try:
            yield
        finally:
            with self._lock:
                self._end(ticket)

    def _wait_for_turn(self, size, request):
        with self._lock:
            ticket = _Ticket(size, _turn_clock(), request)
            # Every hand-over gives the turn to an eligible waiter, so a free turn has none: a body that may take
            # it takes it without waiting and without passing anyone.
            if self._holder is None and request not in self._analysing:
                self._give(ticket, ticket.since)
                return ticket
            self._waiting.append(ticket)
        try:
            while not ticket.wait(ANALYSIS_STUCK_POLL_S):
                with self._lock:
                    # Re-read under the lock, where every hand-over happens: a ticket set just as its wait ran out
                    # holds the turn, and its own holding must never be taken for a stuck one.
                    if ticket.is_set():
                        continue
                    # A free turn with an eligible waiter is lost too, to a defect in passing it on: same recovery.
                    lost = self._holder is None or _turn_clock() - self._since > ANALYSIS_STUCK_S
                    if lost and self._eligible():
                        logger.error("Analysis turn presumed lost (held for more than %s s, or free with bodies "
                                     "waiting): passed on", ANALYSIS_STUCK_S)
                        self._hand_over()
        except BaseException:
            # A wait that fails must leave neither the turn with this body nor its ticket in the queue, or every
            # later body would wait for the safety valve.
            with self._lock:
                if ticket.is_set():
                    self._end(ticket)
                else:
                    self._waiting.remove(ticket)
            raise
        return ticket

    def _eligible(self):
        """With `_lock` held: the waiting tickets that may take the turn, in arrival order."""
        return [t for t in self._waiting if t.request not in self._analysing]

    def _give(self, ticket, now):
        """With `_lock` held."""
        self._holder, self._since = ticket, now
        self._analysing.add(ticket.request)
        ticket.set()

    def _end(self, ticket):
        """With `_lock` held: the body of `ticket` is out of the analysis, or never entered it."""
        self._analysing.discard(ticket.request)
        # Its siblings may take the turn now: if it is free they get it at once, not at a valve check. A body whose
        # turn the safety valve gave away has no turn of its own to pass on.
        if self._holder is ticket or self._holder is None:
            self._hand_over()

    def _hand_over(self):
        """With `_lock` held."""
        eligible = self._eligible()
        if not eligible:
            self._holder = None
            return
        now = _turn_clock()
        # Tickets are queued in arrival order on a monotonic clock, so the first has waited longest: once aged it
        # goes first. Otherwise the shortest body, and `min` keeps the first arrival among equal sizes.
        oldest = eligible[0]
        chosen = oldest if now - oldest.since > ANALYSIS_AGING_S else min(eligible, key=lambda t: t.size)
        self._waiting.remove(chosen)
        # Handed over without being freed: a body arriving in between cannot jump the queue.
        self._give(chosen, now)


_ANALYSIS_TURN = _AnalysisTurn()


@app.get("/health")
def health():
    return {"status": "healthy", "service": "http-fingerprint", "version": "4.0.0"}


@router.get("/http", tags=["HTTP Fingerprint"])
def http_check(
    domain: str = Query(..., min_length=4, max_length=253, pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"),
    check_www: bool = Query(True),
    brand_keywords: str = Query("", description="Comma-separated brand keywords"),
    detect_hidden: bool = Query(True, description="Rileva tag nascosti e contenuto offuscato")
):
    logger.info(f"Check: {sanitize_log_input(domain)} www={check_www} hidden={detect_hidden}")
    targets = [domain]
    if check_www:
        targets.append(f"www.{domain}")

    patterns = DEFAULT_SUSPICIOUS_PATTERNS.copy()
    if brand_keywords:
        for kw in brand_keywords.split(","):
            kw = kw.strip()
            if kw:
                patterns.append(re.escape(kw))

    result = {
        "domain": domain, "timestamp": now_iso(),
        "checks": [],
        "overall_status": "down",
        "hidden_elements_risk": 0,
        "error": None
    }

    from concurrent.futures import ThreadPoolExecutor

    # Build list of URLs to fetch
    urls = [f"{scheme}://{target}" for target in targets for scheme in ["http", "https"]]

    # This request in the analysis turn, which never gives the turn to one of its bodies while another is in analysis.
    request_key = object()

    def _fetch_and_analyze(url):
        resp = http_get_with_retry(url, timeout=HTTP_TIMEOUT)
        check = {
            "url": url,
            "status_code": resp["status_code"],
            "content_length": len(resp["content"]) if resp["content"] else 0,
            "title": None,
            "server": resp["headers"].get("Server", resp["headers"].get("server", "")),
            "content_hash": None,
            "content_hash_canonical": None,
            "visible_text_hash": None,
            "suspicious_patterns": [],
            "hidden_elements": None,
            "redirect_chain": resp["final_url"],
            "error": resp["error"]
        }
        is_active = False
        risk = 0

        if resp["status_code"] and resp["status_code"] < 400 and resp["content"]:
            is_active = True
            html = resp["content"].decode("utf-8", errors="replace") if isinstance(resp["content"], bytes) else resp["content"]
            check["content_hash"] = content_hash(html)
            with _ANALYSIS_TURN.take(len(html), request_key):
                check["content_hash_canonical"] = content_hash(normalize_html_for_fingerprint(html))
                check["visible_text_hash"] = content_hash(extract_visible_text(html))

                title = extract_title(html)
                check["title"] = title.strip()[:200] if title is not None else None

                check["suspicious_patterns"] = detect_suspicious_patterns(html, patterns)

                if detect_hidden:
                    hidden = detect_hidden_elements(html, self_domain=domain)
                    check["hidden_elements"] = hidden
                    risk = hidden.get("risk_indicators", 0)

        return check, is_active, risk

    any_active = False
    max_hidden_risk = 0
    # Fetch all URLs in parallel, preserve order
    with ThreadPoolExecutor(max_workers=max(len(urls), 1)) as ex:
        for check, is_active, risk in ex.map(_fetch_and_analyze, urls):
            result["checks"].append(check)
            if is_active:
                any_active = True
            if risk > max_hidden_risk:
                max_hidden_risk = risk

    if any_active:
        result["overall_status"] = "active"
    elif any(c["status_code"] and c["status_code"] >= 400 for c in result["checks"]):
        result["overall_status"] = "error"

    result["hidden_elements_risk"] = max_hidden_risk

    return JSONResponse(content=result)

app.include_router(router)
