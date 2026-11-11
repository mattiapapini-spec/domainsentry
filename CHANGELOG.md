# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### CI
- **The CI workflow ran with the default permissions of the repository's token (`BUILD-14`).**
  `.github/workflows/ci.yml` had no `permissions:` block, so its jobs received whatever the
  repository grants the GitHub token by default, which can include write access. The workflow now
  declares `permissions: contents: read`: the `lint`, `test` and `docker` jobs only check out,
  install, test and build locally, and none of them writes to the repository or publishes
  anything. Triggers, jobs and steps are unchanged. Checked on the file, not on a run of GitHub
  Actions.

### Documentation
- **The documentation was not ready for a public repository (`DOC-02`).** `LICENSE` named no
  copyright holder; there was no security policy, and `CONTRIBUTING.md` asked to "email directly"
  with no address; the README counted 17 DKIM selectors where `/dns` tests 18, listed 11
  configuration variables, started local services without `SERVICE_HOST`, so on every interface,
  and had outdated development and test instructions and an outdated roadmap; nothing described
  the operating limits of a deployment; and three regular expressions copied from CPython carried
  no attribution. **What changes.** Documentation and one comment only: no code, configuration or
  behavior changes. `LICENSE` names the copyright holder. A new `SECURITY.md` asks for private
  reports through GitHub's private vulnerability reporting and sets the scope on the two trust
  zones: the authenticated zone, and the unauthenticated engine, which must stay on an internal
  network or loopback. The README counts the 18 selectors of `shared/constants.py`; describes the
  status of each DNS query, the 40 s deadlines of `/dns` and `/reputation` and the rule that a
  failure is not an absence; documents 33 configuration variables instead of 11, and which ones
  the compose files actually pass to the container; adds an "Operating limits" section; starts
  local services with `SERVICE_HOST=127.0.0.1`, because `run_service.py` listens on `0.0.0.0`
  when it is not set; and explains the parallel test driver, the `node` needed by the dashboard
  rendering tests, the fixed temporary paths of some tests and how to stop the driver.
  `CONTRIBUTING.md` installs the pinned development dependencies, gives the test commands, adds a
  pull-request checklist (a failing regression test first, a changelog entry with numbers, only
  `.example` domains and RFC 5737 addresses) and points to `SECURITY.md`. A comment in
  `shared/utils.py` attributes the three expressions to CPython's `Lib/html/parser.py` under the
  Python Software Foundation License.

### Fixed
- **The orchestrator lost results without saying so when classification, diff, event publishing or
  discovery failed (`COL-29`).** A domain whose classification failed disappeared from the events of
  the cycle; a failed `/diff` (or a history that could not be written) let the snapshot be
  overwritten, and the change of that cycle never came out; "Pubblicati N eventi" was logged also
  when `/publish` answered with an error; a dnstwist HTTP error left no trace; and the run ended
  `done` with nothing to show. **What changes.** A domain whose classifier did not answer still
  reaches the events, with the fallback classification `needs_review` and rule
  `classification_unavailable`; that event is not ingested as a case, since it would overwrite the
  classification of open cases. After a failed diff the snapshot is still updated (invalid data must
  not stop it, `COL-16`, and a diff that fails on the same data would fail at every cycle), but it
  keeps the baseline of the last successful diff (`diff_baseline`, not shown by `/intel`): the next
  diff starts from there and the change comes out then; a diff without changes is not a failure.
  `/publish` now lists in `failed` every enabled target that did not write (it answered 200 with an
  empty `targets` before, the same as a disabled target), and the orchestrator does not log
  "Pubblicati N eventi" when the answer is an error or a target failed. A domain without a
  classification is written to the file for the SIEM but not sent to the chat webhook: with the
  classifier down it would be one message per domain. On the dnstwist variants, a classification that
  fails is logged and counted (the event keeps the discovery placeholder), and an error while saving
  the snapshot no longer skips the classification of the variant. Failed discovery is logged, the log
  of the classifier and dnstwist errors is sanitized, and every failure of the run is counted in
  `/progress` under `failures` (`classification`, `diff`, `store`, `publish`, `discovery`). 23
  regression tests in `tests/test_pipeline_failures_col29.py`.
- **With the capacity filter alone, an anonymous flood on the collectors also took the places the
  legitimate scan needs (`PERF-08`, with the accounting of abandoned scan requests).** **What
  changes.** 8 places are reserved to the requests of the orchestrator, recognised by the
  `X-DomainSentry-Scan` header with a random mark generated at every start of the process and never
  exposed (compared in constant time); with the reserve full the scan uses the anonymous places. A
  scan request older than the `SERVICE_TIMEOUT` of the orchestrator has already been abandoned, since
  the orchestrator always gives up at that threshold, but its thread is still busy: it moves to a
  separate count of at most 4 places, with a line in the log, and the reserve goes back to the live
  scan. At most 20 + 8 + 4 = 32 collector requests run at once, of the 40 threads. The orchestrator
  sends the mark from its HTTP session, so in the unified deployment every orchestrator call carries it;
  all those URLs point to the same process there. 11 regression tests in
  `tests/test_unified_capacity_perf08.py`.
- **In the unified process, slow requests to the collectors could take every thread and make the rest
  of the service unreachable, health probe included (`PERF-04`, capacity filter).** The synchronous
  handlers of every service share the 40 threads of the anyio pool. Measured on the code before this
  change: with 45 concurrent `/whois` requests of 1.5 s each, `/health` answered after 1.06 s instead
  of at once. **What changes.** An ASGI filter in `unified.py`, before the thread pool, admits at most
  20 requests to `/dns`, `/cert`, `/http`, `/whois` and `/reputation` together, 8 per collector and
  4 for reputation; for WHOIS the places follow its turn queue (`PERF-02`): every admitted request
  books a turn `WHOIS_DELAY` apart, so the places leave two turns of margin within
  `WHOIS_MAX_WAIT_S`, 4 with the default settings, otherwise even a request of the scan would find no
  turn. The others get a 503 with `Retry-After: 5` at once, without taking a thread, and the refusals
  are logged at most once every 10 s with their counts. The path is read without the `root_path`, as
  Starlette routes it, so a deployment behind a prefix does not switch the filter off. A place comes back when the
  handler really ends, not when the caller stops waiting, since its thread is busy until then. The
  other paths do not go through the filter. In this change the scan of the orchestrator counts like
  any other caller: its reserve is `PERF-08`. The split deployment (`docker-compose.prod.yml`) is
  not affected. 31 regression tests in `tests/test_unified_capacity_perf04.py`.
- **The WHOIS service waited for its turn while holding the rate lock, so concurrent requests queued
  without limit (`PERF-02`, WHOIS part).** `whois_check` slept until `WHOIS_DELAY` had passed since the
  last query with `_rate_lock` held: concurrent requests lined up one behind the other, each holding a
  thread of the pool that the unified process shares with the dashboard and the login, and the k-th
  waited about k × `WHOIS_DELAY` with no bound. **What changes.** The turn is booked under the lock and
  waited for outside it, on the monotonic clock (a step back of the system clock would otherwise block
  the queries for as long as the step); the minimum spacing between two queries stays `WHOIS_DELAY`. A
  request that would wait more than `WHOIS_MAX_WAIT_S` (12 s) answers at once with a fixed error, not
  cached: the module is not collected and the previous cycle is carried over, as for VirusTotal
  without a quota slot (`PERF-05`). Worst case of a request: 12 s of turn, 15 s of lookup and 8 + 8 s
  for the parsing child, 43 s against the 45 s of the orchestrator. The reputation side was already
  bounded by `PERF-05`. 6 regression tests in `tests/test_whois_rate_wait_perf02.py`.
- **No limit on the `dig` processes of the whole service (`PERF-04`, process cap only).** After
  `SEC-29` one `/dns` request starts up to 10 `dig` at once, 7 already with `full=false`, and
  concurrent requests multiplied them with no ceiling. **What changes.** At most `DIG_MAX_PROCESSES`
  (20, two complete requests) run in the whole process. A query that finds no place within the time
  it has left is `unknown`, like every query without an answer, never "no record"; the wait for a
  place is taken from the time of the process, so the deadline of `SEC-29` stays that of the request,
  and with a free place the process ceiling is the same as before. The capacity filter of `PERF-04`
  (with `PERF-02` and `PERF-08`) is not part of this change. 5 regression tests in
  `tests/test_dig_process_cap_perf04.py`.
- **An error answer from an intelligence service became "no data" without a line in the log
  (`CODE-71`).** `_fetch_service` returned `None` for any answer that was not ok, and only exceptions
  were logged: a 500 from `/http` could not be told from a service with nothing to say. **What
  changes.** An error answer is still no data for that module, and now logs a warning with the
  service, the HTTP status and the URL. 6 regression tests in
  `tests/test_service_error_logged_code71.py`.
- **A body analysis that failed lowered the risk of the domain instead of being a signal
  (`CODE-68`).** An exception while downloading or analysing one page left `/http` with an error:
  the four checks were lost, the `http` section reached the classifier empty, and neither the active
  site nor its hidden elements counted any more (a young domain went from HIGH to MEDIUM). Whoever
  serves the page chooses its markup, so the failure is theirs to cause. **What changes.** A failure
  stays on its URL: a download that raises is an unreached URL (`error: "fetch failed"`), an analysis
  that raises gives `analysis_failed: true` and no `hidden_elements`; the other URLs keep their
  analysis, and the log names the URL and the exception class, not its message. `MemoryError` speaks
  of the process, not of the page, and still fails the request. The classifier reads the flag, only
  when it is `true`, at the top of its rules: `suspicious`/high (`body_analysis_failed`), or
  `needs_review` on a domain that predates the campaign, as for hidden elements; it comes before the
  parking and the substantial-content rules, because a failed check is still an active site and would
  otherwise count as parking or as legitimate. The diff raises `legit_body_analysis_failed` on the
  client's legitimate domain at every cycle the page keeps failing, since no other signal is left on
  that URL, and `body_analysis_failed` elsewhere the first cycle a URL fails; both HIGH (a page that
  could not be checked, not an observed injection). 20 regression tests in
  `tests/test_body_analysis_failure_code68.py`.
- **The parse of a page depended on the patch level of Python: on older versions a few bytes of markup
  made the body analysis of `/http` fail, on newer ones a `<![CDATA[` hid the markup after it
  (`SEC-51`).** Up to CPython 3.12.11 `HTMLParser` hands every `<![` to
  `_markupbase.ParserBase.parse_marked_section`, which raises `AssertionError` on an unknown keyword,
  and calls `set_cdata_mode` without the `escapable` argument that `_TagCollector` passed on, so every
  page with `<script>` or `<style>` failed as well. From 3.12.12 (and in 3.13) the library opens a real
  CDATA section on `<![CDATA[` up to `]]>`, while the browser, in HTML content, ends it at the first
  `>`: the tags in between were invisible to the analysis and live in the page. Measured with
  standalone CPython builds: 3.12.3, 3.12.8, 3.12.10 and 3.12.11 raise, 3.12.12 and 3.13 hide.
  **What changes.** `_TagCollector` reads every `<![` up to the first `>` on every version (CDATA
  support switched off where the library has it, the marked-section grammar replaced where it does
  not), and passes on to `set_cdata_mode` only what the library gives it. On CPython 3.12.3 the whole
  detector suite now passes, where ten tests failed before. Inside `<svg>` or `<math>` the browser
  keeps CDATA, so markup there can now be counted when it is only text: over-counting, never hiding.
  The oracle of the `SEC-48` and `SEC-50` equivalence tests now keeps `reset` and
  `parse_marked_section` of the collector, as it already kept `set_cdata_mode`: they are its grammar,
  not library parsing. 11 regression tests in `tests/test_marked_section_sec51.py`; the end-to-end
  ones are red only on the versions they describe.
- **The version constraint on urllib3 allowed versions on which the decompression-bomb cap of
  `SEC-16` does not hold (`SEC-22`).** `requirements.txt` asked for `urllib3>=2,<3`, and the image
  installs from it at build time. Measured with `TestFetchDecompressionBombGuardrail` (requests
  2.32.3, Python 3.12): from 2.0.0 to 2.6.1 the chunked + gzip case decompressed a single chunk of
  about 20 MB against a threshold of 32 KB; from 2.6.2 (2.6.2, 2.6.3, 2.7.0, 2.8.0) both cases pass.
  **What changes.** The constraint is `urllib3>=2.6.2,<3`; the requirements still resolve to the same
  versions today (urllib3 2.8.0). A new test checks the constraint against the measured versions and
  the installed urllib3 against the constraint, using `packaging`, already installed with pytest. An
  image built before this change may carry an older urllib3: check it with
  `python3 -c "import urllib3; print(urllib3.__version__)"` in the container. 11 regression tests in
  `tests/test_urllib3_constraint_sec22.py`.
- **`collection_status` of `/classify/variant`, in the unauthenticated zone, was a free dictionary
  (`CODE-31`).** Any key of any length was accepted and ended in the rationale of the collection
  guard (`CODE-30` capped it downstream), and any truthy value, the string `"false"` included,
  declared a section failed. **What changes.** Only `dns`, `cert`, `http`, `whois` and `reputation`
  are accepted, each with a boolean; anything else is rejected with 422, also inside
  `/classify/batch`. The orchestrator sends only those keys with booleans, so nothing changes for it.
  The two `CODE-30` tests that classified with a 2,000-character key now check that the key is
  rejected; the cap on the template stays as defence in depth. 18 regression tests in
  `tests/test_collection_status_validated_code31.py`.
- **The orchestrator put the domain into the URLs of the internal services without encoding it
  (`SEC-14`).** `/dns`, `/cert`, `/http`, `/whois`, `/reputation`, the dnstwist call and the WHOIS-only
  lookup of a dormant homoglyph were built as `?domain={domain}&…`: a `&`, `#` or `?` in the name
  could change the other parameters of the internal call, and only the domain pattern of each service
  stood in the way. **What changes.** The domain is percent-encoded in all seven URLs, so the service
  receives exactly the name and the orchestrator's own parameters stay as they are; a malformed name
  is now rejected by the service as a whole. For an ordinary domain the URLs are identical to before.
  4 regression tests in `tests/test_internal_urls_encoded_sec14.py`.
- **A `/diff` that answered with an HTTP error left no line in the log (`CODE-43`).** `_persist_intel`
  logged only the exceptions of the call: with a 500 the comparison with the previous cycle was lost
  without a trace. **What changes.** An error answer (4xx or 5xx) logs a warning with the domain and the status.
  The snapshot is still overwritten in that case, as before: keeping the change for the next cycle is
  part of `COL-29`. 5 regression tests in `tests/test_persist_intel_diff_log_code43.py`.
- **With `INTEL_STORE=false` the pipeline still wrote snapshots and history for dnstwist variants
  (`OPS-06`).** The loop over the feed domains checked the flag; the `variant_intel` branch called
  `_persist_intel` for every resolving variant anyway, which saved the snapshot under `INTEL_DIR` and,
  with an earlier snapshot, called `/diff` and appended the history. **What changes.** The variant
  branch checks the same flag: with the store off nothing is written and no `/diff` is called, while
  the variant is still collected and classified with its intel. With the store off, the homoglyph
  WHOIS reused by `SCO-05` after a restart can only come from the in-process cache, as the flag
  implies. 4 regression tests in `tests/test_variant_intel_store_flag_ops06.py`.
- **A variant found by dnstwist kept the fixed `needs_review` label whenever its intel was not
  collected, and the classifier was never asked (`CODE-17`).** Without `variant_intel`, and with it
  for a variant that does not resolve and is not a homoglyph, the event carried the discovery
  placeholder (`dnstwist_discovery`, confidence `low`): the rules on the name alone, such as the
  script mixing of a homoglyph, never applied to these variants. **What changes.** Such a variant is
  sent to `/classify/variant` with its name and fuzzer, an empty `collection_status` and, for a
  homoglyph, the WHOIS already observed in an earlier cycle (`SCO-05`, no network call): no module is
  declared, so nothing that was not collected is read as absent. A homoglyph with mixed scripts and no
  known WHOIS now becomes `suspicious` (HIGH case severity) also without `variant_intel`, while one
  whose known WHOIS predates the campaign stays LOW; a variant that no rule matches stays
  `needs_review`, with the classifier's rule instead of the placeholder. The call has the 10 s
  timeout of the classification of the feed domains, one call per variant. If the classifier fails
  or does not answer, the placeholder stays and the event is still published. On the first cycle
  after the update, homoglyph variants of a client may move from MEDIUM to HIGH. 8 regression tests in
  `tests/test_variant_discovery_classified_code17.py`.
- **A certificate name that was not a string made `/classify/variant` fail with a 500, and the domain
  stayed without a classification for that cycle (`CODE-18`).** crt.sh can return
  `"common_name": null`: when that is the only certificate name of a domain, `cert_intel` passes
  `[None]` in `unique_cn`, and `/classify/variant`, in the unauthenticated zone, takes the payload as
  it comes. The classifier compared every element with the enterprise certificate providers, and a
  `None` (or a number) raised `TypeError`.
  **What changes.** The classifier reads only the elements of `unique_cn` that are strings, and a
  `unique_cn` that is not a list counts as empty: a null next to an enterprise provider still finds
  it, and a list of nulls classifies like an empty list. 11 regression tests in
  `tests/test_classifier_cert_names_code18.py`.
- **A form or an iframe hidden with the HTML5 `hidden` attribute was not detected (`CLS-01p`).**
  `hidden_forms` looked only at `style` and at `class`, `invisible_iframes` only at the size and at
  `style`: `<form hidden action=…>` raised nothing, while the browser does not show the element.
  **What changes.** A form with the attribute, whatever its value, is hidden, with `technique`
  `hidden_attribute` (`css_hidden` stays when the style or the class already hide it, so the output of
  those forms does not change); an iframe with the attribute is invisible and `hidden_attribute` joins
  its other techniques. Forms and iframes in the fallback content of a closed `<iframe>` stay out, as
  before. On the first cycle after the update, a monitored legitimate domain that already hides a form
  or an iframe this way raises the matching alert once. 22 regression tests in
  `tests/test_hidden_attribute_cls01p.py`.
- **Hidden inputs were still read with a text scan after forms, iframes and pixels had moved to the
  tokenizer, so a page could hide them or report them wrong (`CLS-01u`).** Valid markup could keep a
  hidden input out of the scan, names and values were cut short, and inputs that the browser does not
  treat as hidden were counted. **What changes.** `detect_hidden_elements` reads `<input>`
  from the same single parse as forms, iframes and pixels (`SEC-48`, no second pass on the page): an
  input is hidden when its first `type` is `hidden` in any case; `name` and `value` are the whole
  values as the browser submits them (entities decoded), without control characters, the name capped
  at 300 characters and the value at 100 as before. As for the other tokenizer categories, inputs in
  HTML comments, in the fallback content of a closed `<iframe>` and inside `<script>`/`<style>` are not
  live markup and are no longer counted. The inputs collected by the parse never count as dead markup
  (`CLS-01z` still reads only iframes, forms and images). The random corpus of
  `test_http_body_analysis_sec47.py` checks only the lists read by regex, so `hidden_inputs` leaves it
  (45 of its 80 expected signatures recomputed): on those 80 documents and on the 9 readable pages
  every other list is identical before and after. 15 regression tests in
  `tests/test_hidden_inputs_cls01u.py`.
- **A request to `/reputation` could take up to about 105 s, while the orchestrator gives up after
  45 s; the abandoned request still spent a VirusTotal quota slot and the OTX and SecurityTrails
  calls on a result that was lost, and the domain lost its reputation section and became
  `insufficient_data` (`PERF-05`).** `reputation_check` (`services/reputation.py`) called
  VirusTotal, OTX and SecurityTrails one after the other, each with `timeout=15`. Before the
  VirusTotal call, `_vt_wait_for_slot` waits for a slot of the quota (`PERF-01`, 4 calls per 60 s by
  default); with the quota exhausted it slept up to 60 s while holding the quota lock, with no limit
  on the sleep or on the wait for the lock, so the other requests queued behind it. The orchestrator
  stops waiting for a service after `SERVICE_TIMEOUT`, 45 s by default, and records no answer, while
  the handler goes on. Measured on the code before this change with a fake network: with the quota
  exhausted, the last of 8 concurrent requesters got its slot after 119.9 s and the last of 12 after
  179.9 s, almost all of it spent waiting for the lock; with the quota exhausted and three sources
  that never answer, a request took 105.1 s, and 45.1 s with the quota free. The `timeout=` of
  `requests` bounds each connect and each read, not the call: on loopback with `timeout=1`, a reply
  that trickled in took 10.01 s and a name behind a resolver that did not answer took 4.00 s. Down
  the real chain (`unified`, orchestrator, intel store, classifier) with 50 domains at a fast pace,
  the orchestrator abandoned 12 requests, every fourth domain, the rhythm of the quota window. Their
  handlers still made the GETs to VirusTotal, OTX and SecurityTrails 6.7 to 8.3 s after the
  orchestrator had given up: 12 VirusTotal calls of 50 were wasted, and OTX and SecurityTrails were
  called for 50 domains and observed for 38. Each abandoned domain had its whole reputation section
  carried over from the previous cycle as a failed module, and its event became `insufficient_data`
  (`CODE-23`) instead of the classification of its data. **What changes.** Only
  `services/reputation.py` (109 lines added, 11 removed); standard library only. Each request to
  `/reputation` has a deadline of 40 s, `REPUTATION_DEADLINE_S`, taken when the handler starts. The
  requested sources run in parallel, one thread each, and the handler waits for them at most until
  the deadline: OTX and SecurityTrails do not wait behind the VirusTotal slot, and the timeouts do
  not add up. The wait for a VirusTotal slot, lock included, lasts at most 35 s, `VT_MAX_WAIT_S`,
  and never past the deadline: the lock is taken with a timeout, the sleep stops at the limit and
  the window is read again after it. With no slot by then, VirusTotal is skipped for that domain: no
  slot is taken and no GET is made, during the request or after the response, also when the
  scheduler wakes the waiting thread or starts the sources late. The `timeout=` of each GET is the
  smaller of 15 s, `REPUTATION_HTTP_TIMEOUT_S`, and the time left, and no GET starts once the
  deadline has passed. A skipped VirusTotal, and a source not reached by the deadline, is a dict
  with the zeros of that source and a fixed non-empty `error` ("skipped: VT quota slot not available
  within the wait limit", "no answer within the request deadline"): never `None`, which means a
  source not requested or without a key, and never the text of a VirusTotal 404
  (`VT_NOT_FOUND_ERROR`), which is an observation. Downstream it is a source not observed, carried
  over from the previous cycle (`COL-16`) with no alert. With no slot in sight the request waits up
  to the limit rather than giving up at once: giving up at once makes the orchestrator run through
  the following domains with the quota still exhausted, and in the design measurements a prototype
  that did so observed VirusTotal for 12 to 20 domains of 50 at a fast pace, against 40. The
  configuration guards of `PERF-01` raise at once, also with the quota exhausted. The signatures of
  `_check_vt(domain)` and `_vt_wait_for_slot()` do not change; the deadline reaches the source
  threads through a thread-local value, and outside a request `_check_vt` keeps only the 35 s limit
  and the full timeout, a use no service makes. No endpoint, trust zone, dependency, port,
  `Dockerfile`, SQLite schema or persisted format is touched, so a rollback restores the previous code with
  no migration. **Measured.** At real scale (40, 35 and 15 s, a 60 s window of 4 slots, fake
  network, real sleeps), in two series on the final code, one by the author of the change and one by
  the independent verification: with 8 concurrent requests, the quota exhausted and one slot freed
  at 34 s, 7 answer at 35.02 to 35.05 s with VirusTotal skipped and the one that gets the slot at
  40.01 to 40.02 s; with three GETs that ignore their timeout for 60 s the answer comes at 40.02 s,
  the three sources marked as not reached, and at 40.03 to 40.05 s for 8 concurrent requests; three
  silent sources that honour their timeout give 15.02 s. The latest answer came 0.05 s after the
  deadline, 4.95 s before the orchestrator gives up; no VirusTotal GET started after the deadline
  and no slot was taken without a GET. Down the real chain with 50 domains at a fast pace, every
  request is answered: VirusTotal observed for 40 domains and skipped for 10 at the limit, 0 calls
  wasted, OTX and SecurityTrails observed for 50 of 50, and no `insufficient_data` against 12. At a
  medium pace, where every quota wait of the code before this change stays under 35 s, snapshots and
  events are byte-identical to that code. Over consecutive cycles of the real orchestrator and
  classifier, a skipped VirusTotal is carried over on its own and the saved risk is recomputed on
  the carried value; the risk score of the event of that cycle leaves VirusTotal out, as for any
  VirusTotal error. In 10 sequences no false `vt_malicious_detected` appears, before or after a
  skip; the only CRITICAL alerts are true changes from 0 to 3 detections, the same as with the code
  before this change. The quota is never exceeded: 24 concurrent requesters, handlers and direct
  calls mixed, took 64 slots for 64 GETs, at most 4 in any window. 70 tests sit in a module of their
  own, `tests/test_reputation_deadline_perf05.py` (1,020 lines), on a fake network with real time
  scaled down. On the code before this change 36 fail and 34 pass; the 34 are controls: the quota,
  waits under the limit, the `PERF-01` guards, the stubbed slot wait used by other tests and the
  shape of failed sources. The others pin the limit of the wait, lock included, and its lower bound,
  so that no request gives up early; the answer within 10 % of the deadline; slow OTX and
  SecurityTrails observed while VirusTotal waits in vain; each `timeout=` within the time left; a
  scheduler that wakes the slot waiter or starts the sources after the limit; no thread left once
  the GETs end; and the chain down to the real orchestrator and classifier. A first round of
  independent verification returned insufficient on three points, closed in a second round: comments
  and test texts that compared the code with the code it replaced, a tolerance on the answer time
  loose enough to accept a handler 30 % late, and a slot that a late scheduler could still take
  after the limit. Of 33 mutants of the second round 25 are killed. Of the 8 that survive, 5 are
  equivalent or nearly so; one makes the source threads non-daemon, one lets a `timeout=` exceed the
  time left by 10 % with the answer still at the deadline, and one sleeps with another primitive
  than the `time.sleep` of the module and checks the limit only on entry: the tests of a late
  wake-up lengthen that sleep, and their docstring says so. Suite with the parallel driver: 4,206
  tests collected and 4,206 run, 4,205 passed and 1 skipped, in 66.7 s, against 4,136 tests on the
  code before this change. ruff reports 0 violations. Nothing was measured on production data.
  **Release condition.** The 40 s are a constant, not tied at runtime to the `SERVICE_TIMEOUT` of
  the orchestrator. The change holds only while `SERVICE_TIMEOUT` stays above 40 in the environment
  of the service (45 by default; the compose files do not set it): with 40 or less the orchestrator
  gives up first and the abandoned request behaves as described above. **Accepted and declared
  limits.** (1) With quota waits between 35 and 45 s, VirusTotal is skipped where the code before
  this change read it within the 45 s of the orchestrator: an event model of the pipeline, validated
  against the real chain, gives 5 to 10 skips out of 50 domains in that band. This is the chosen
  design: a fixed limit that leaves time for the call. (2) A GET still running when the deadline
  passes is not interrupted: its thread ends on its own with the GET and the result is dropped. The
  endpoints are the fixed APIs of the three providers, not hosts chosen by the caller, and such a
  thread holds no worker of the shared pool and no quota slot it has not already used. Under a
  sustained flood of anonymous requests while those APIs do not answer, the live threads grow with
  the duration of the pending GETs. Measured at one tenth of real time with every worker of the pool
  busy: a peak of 165 threads with sources that honour their timeout, back to 45 once drained, and
  249 with GETs that ignore it for 60 s. The code before this change stayed at 45 threads because
  the VirusTotal wait held the requests in the pool one after the other, and under the same flood
  its answers came an order of magnitude later than with this change. (3) If the process cannot
  start a thread, `/reputation` answers 500 and the orchestrator reads the module as failed, as when
  it gets no answer. (4) Under such a flood OTX and SecurityTrails are called at the pace of the
  requests rather than held back by the VirusTotal wait; that pace could already be reached with the
  code before this change. (5) When every requested source is skipped or not reached, for instance
  with only the VirusTotal key configured, the module reads as failed and the whole section is
  carried over, as when the orchestrator got no answer. **Tracked separately.** The deadline starts
  when the handler runs, not when the request arrives, so the wait for a free worker of the shared
  pool before it is not covered, and under a flood answers still reach the client after 45 s; this
  goes with the process-wide cap on concurrent work. A skipped VirusTotal is not logged, only its
  `error` in the snapshot. The window of the VirusTotal quota is measured on the system clock rather
  than on a monotonic one. **Declared limit.** The tests and the times come from a development
  machine with Python 3.13, not from the Docker harness of the project or the container, and the
  time the container takes to resolve the names of the three providers was not observed.
- **The dashboard showed a subdomain or DKIM selector carried over from a previous DNS cycle as
  observed in the current one, with no date, and rendered "none found", "not determined" and "no
  data" the same way, while the HTML report read "DNS ok" (`CODE-74`).** `/dns` tests a fixed list
  of 25 subdomains and 18 DKIM selectors one name at a time and lists a name without an answer in
  `subdomains.unknown` or `dkim.selectors_unknown`. Since `COL-31` the orchestrator keeps a name
  found in the previous cycle and undetermined in this one in `subdomains.active` or
  `dkim.selectors_found`, and marks it in `subdomains.carried_over` or
  `email_auth.dkim.carried_over`. The Intel tab (`services/dashboard_app.html`) read only the two
  lists of found names: a carried name was shown as observed in the cycle, with no sign and no date;
  with no found name the subdomain block and the DKIM row were missing, so a zone with no subdomain,
  a zone whose names did not answer and a section with no data rendered byte-identical; and the
  "Module status" line of the HTML report read "DNS ok" with names undetermined or carried. **What
  changes.** Only `services/dashboard_app.html` (60 lines added, 4 removed); no Python. Two
  top-level helpers, shared by the Intel tab and the report, read the names from the lists, never
  from the keys of a marker. A found name is carried only when the marker of its own section has an
  own entry for it (`Object.prototype.hasOwnProperty.call`, so `constructor` or `__proto__` are
  names like any other) that is an object with a non-empty string `carried_at`; the marker is never
  copied. The undetermined names are the strings in `unknown` or `selectors_unknown` that are not
  found, each counted once through a `Set`: a carried name, listed in both, is not counted twice,
  and the cost stays linear. In the Intel tab a carried subdomain or selector reads "(riportato,
  ultima osservazione: AAAA-MM-GG HH:MM)" beside its name, or "data ignota" when `observed_at` is
  not a non-empty string; undetermined names get a line of their own, "sottodomini non determinati
  (il DNS non ha risposto): N (names)" and "selettori non determinati (il DNS non ha risposto): N
  (names)", and the subdomain block appears as "Subdomains (0)" when no subdomain is active. "nessun
  sottodominio attivo (25 provati, ultima osservazione: …)" and "nessun selettore trovato (18
  provati, ultima osservazione: …)" appear only when the section carries its list of undetermined
  names, nothing is found, nothing is undetermined and the number tested is a number. These "none"
  lines carry the date of the DNS section, `dns.timestamp`, or "data ignota": on a total failure, or
  when `/dns` gives the orchestrator no answer, the snapshot keeps the whole previous section
  (`CODE-01`), and with no name `COL-31` has nothing to mark, so a "none" observed in an earlier
  cycle would read as current. A first round of independent verification returned insufficient on
  exactly this case; the date was added in a second round. In a fresh cycle the date is that of the
  cycle; across consecutive failures it stays that of the last observation and moves on only when
  `/dns` answers again. Dates are UTC, cut to the minute, with no time zone shown, like the other
  dates of the tab. The report reads "DNS parti riportate" with a carried part or name, "DNS parti
  non determinate" with an undetermined name, and "DNS ok" otherwise; "errore" and "non raccolto"
  win as before. Every new value goes through `esc()`. No inline handler, CSS class, endpoint, trust
  zone, dependency, port, `Dockerfile` or SQLite schema is touched; the JSON report is unchanged and
  nothing is persisted. Snapshots saved before the lists of undetermined names existed, with
  `subdomains: {tested, active}` and no `selectors_unknown`, render as before and never show a
  "none" line: without those lists an empty section may also be a DNS that did not answer. A
  `selectors_found` that is not a list no longer makes the Intel tab throw. **Measured.** 278 tests
  in a module of their own, `tests/test_dashboard_carried_undetermined_code74.py` (1,281 lines), run
  the real script of the page in node, like the existing rendering tests, on synthetic snapshots and
  on snapshots saved by the real carry-over of `COL-31`: a partial cycle, a cut stage, a total
  failure, a missing answer of `/dns`, a healthy cycle, a cut first cycle, hostile names kept by a
  total failure, and a previous section with no name followed by failures. On the code before this
  change 93 fail and 185 pass; the 185 are controls of what must not change. With this change all
  278 pass, and so do the 468 tests of the existing dashboard modules. Where nothing is
  undetermined, carried or "none", the rendering does not change: of 156 snapshots of real shape (13
  responses of the real `/dns` with a fake `dig`, each raw and in the shape without the lists of
  undetermined names, 45 saved by the real orchestrator, 7 older shapes written by hand and the 78
  fixtures of the existing rendering tests), the 119 with nothing undetermined, carried or "none"
  render byte-identical, tab and report, to the code before this change, and the 78 fixtures and
  every older shape are among them. 58 hostile cases (markup, entities, control characters, lone
  surrogates, very long strings, prototype names, malformed markers) rendered against a benign twin
  differ only by the escaped text; 8,000 random snapshots raise no new exception and 376 fewer than
  the code before this change; 3,000 random section timestamps give no violation and no exception.
  The cost is counted, not timed: the elements scanned by array methods grow ×7.9 from 300 to 2,400
  names, against ×63.8 for a known quadratic scan; 80,000 names render in 509 ms, while `/dns`
  writes at most 25 + 18. Of 68 mutants of the independent verification the 14 that survive are
  equivalent, change only the format of a date or the precedence between two report states that are
  not "ok", or need a shape that neither `/dns` nor the orchestrator writes. Suite with the parallel
  driver: 4,136 tests collected and 4,136 run, 4,135 passed and 1 skipped, in 67.9 s, against 3,858
  tests on the code before this change. ruff reports 0 violations. Nothing was measured on
  production data. **Release condition.** This change completes `COL-31` and must be released
  together with it: with `COL-31` alone the dashboard shows a carried subdomain or selector as
  current, with no sign and no date. A rollback restores the previous code with no migration, and
  rolling back this change alone brings that state back, so `COL-31` must be rolled back as well
  before a release.
  **Accepted and declared limits.** (1) Dates are UTC with no time zone shown. (2) The date of a
  "none" line is the `timestamp` of the `/dns` request, taken when the request starts; the name
  stage can end up to about 40 s later (`SEC-29`), below the minute shown. (3) With both carried and
  undetermined names the report reads "parti riportate". (4) A snapshot that lists a found name also
  as undetermined, with no valid marker entry for it, shows that name as fresh; neither `/dns` nor
  the orchestrator writes that shape. (5) A number of names tested that makes no sense, negative or
  huge, is printed as it is; `/dns` writes the length of its list. **Tracked separately**, all
  present before this change: the Intel tab still throws on some malformed snapshots; the "Module
  status" line still reads "DNS ok" when base record types are undetermined and not carried over;
  and an interaction with a separate fix to the SPF and DMARC rows of the Intel tab, after which a
  "none" DKIM line would take the place of "no DNS records". **Declared limit.** The tests and the
  times come from a development machine with Python 3.13 and node 22, not from the Docker harness of
  the project or the container, and the rendering was checked in a node `vm` and with `html.parser`,
  not in a browser.
- **When a DNS cycle left some subdomains or DKIM selectors undetermined, the snapshot dropped them:
  an active subdomain such as `login.` disappeared from the analyst's view with no alert and no
  sign, and came back at the next complete cycle (`COL-31`).** `/dns` (`services/dns_intel.py`)
  tests a fixed list of 25 subdomains, A then CNAME, and 18 DKIM selectors, one name at a time. A
  name without an answer, because of a SERVFAIL, a transport error or the 40 s deadline of the
  request (`SEC-29`), is listed in `subdomains.unknown` or `dkim.selectors_unknown` and is missing
  from `subdomains.active` or `dkim.selectors_found`. The orchestrator (`services/orchestrator.py`)
  carries an undetermined part over from the previous cycle for the 7 base record types and for SPF,
  DMARC, BIMI and CAA (`COL-02`, `COL-12`), but it left the subdomains and DKIM out on purpose,
  because no alert and no rule reads them, and saved the two lists as the cycle returned them.
  Measured down the real chain (`/dns` with a fake `dig`, orchestrator, intel store, classifier and
  the dashboard's own script) with the default settings: two silent names in serial stages, the AAAA
  record and `_dmarc`, made `/dns` stop at 40.02 s with 25 of 25 subdomains and 18 of 18 selectors
  undetermined. The snapshot held no active subdomain and no selector, and the dashboard showed
  neither the subdomain block nor the DKIM row. With one silent name only that name disappeared, and
  the module status of the report read "DNS ok". On a total failure, or when `/dns` gave the
  orchestrator no answer, the whole previous section was kept (`CODE-01`), names included, but with
  no marker, so they were shown as observed in that cycle. No alert and no classification changed in
  any of these cases. **What changes.** Only `services/orchestrator.py` (115 lines added, 5
  removed); standard library only. After the carry-over of the parts, a name of the fixed list that
  is undetermined in this cycle and was active, or found with its records, in the previous snapshot
  keeps its previous entry, in its position in the list. The list is built on the domain the
  orchestrator is processing, never on the lists or the domain found in the response of `/dns` or on
  disk. Each carried name gets an entry in a marker inside its own section,
  `subdomains.carried_over` and `email_auth.dkim.carried_over`, of the form
  `{name: {observed_at, carried_at}}`. `carried_at` is the instant of the cycle, the same as in the
  marker of the parts (`COL-12`). `observed_at` comes from the entry of the same name in the
  previous section marker, otherwise from the `timestamp` of the previous section, with the rules of
  `COL-12`: `null` when unreadable or later than the cycle. The key is absent when no name is
  carried, and the marker of the parts, `dns.carried_over`, keeps its fixed list of 11 parts. On a
  total failure with a previous snapshot, and when `/dns` gives no answer, the previous section is
  kept as before and its two section markers are rebuilt on every active subdomain and every found
  selector, never copied. A section marker sent by `/dns`, which is in the unauthenticated zone, is
  dropped on every path, including a total failure with no previous snapshot (`SEC-31`).
  `subdomains.unknown` and `dkim.selectors_unknown` stay the observation of the cycle. A name that
  gave a real negative answer (`nxdomain` or `nodata`) is not in those lists and disappears as
  before. There is no expiry, as for the base record types: a threshold would let whoever controls
  the DNS of a lookalike hide a name by staying silent long enough. Complete data are saved exactly
  as `/dns` sent them, key order included; the observation of the cycle, which classification and
  events read, is not modified; no alert is added. The previous entries are referenced, not
  deep-copied: `copy.deepcopy` raises `RecursionError` from about 500 levels of nesting while `json`
  reads and writes 5,000 (Python 3.12.3 and 3.13.16), so a deep copy would make the save of the
  snapshot fail on data the store reads, and nothing modifies the saved section afterwards. No
  endpoint, trust zone, dependency, port, `Dockerfile` or SQLite schema is touched. The snapshot
  gains two optional keys, read only by the orchestrator itself to inherit `observed_at`. Snapshots
  already on disk need no migration; one saved during a cut before this change has nothing to carry
  until a complete cycle fills it again. A rollback restores the previous code with no migration: the code
  before this change does not read the markers, and the next cycle in which `/dns` answers replaces
  them. **Measured.** 104 tests in a module of their own, `tests/test_dns_carry_over_col31.py`
  (1,198 lines), with the fake `dig` of the `SEC-29` tests, so no real query is made and no network
  is used. On the code before this change 58 fail and 46 pass. The 46 are controls of what must not
  change: complete data saved as sent, no name invented, a name that really disappeared stays gone,
  degraded or malformed sections saved without error, no alert along the chain. The other tests pin
  the carry-over and the marker per subdomain and per selector, the position in the list, the total
  failure and the missing answer of `/dns`, the instants of the markers over consecutive cycles with
  the real store and `/diff`, forged section markers, previous values nested 800 levels deep, and a
  chain of 12 cycles from `/dns` to `/classify/variant` and `/diff`: a deadline cut, an unanswered
  name and selector, a total failure, a `/dns` timeout, an A `nxdomain` with an unanswered CNAME, a
  name and a selector that really disappeared, a cut after that, their return, and a cut of the
  first selector alone. Along the chain: 0 alerts in 12 cycles, every call to the classifier
  answered 200, the classification is that of the observation, and the names `/diff` compares change
  only when a name really changes. A rule reading `selectors_found` for an added DKIM selector would
  fire on the return after a cut without the carry-over, and does not with it. An independent run of
  11 cycles over a target domain and a dnstwist variant gave 0 alerts, the same events and
  classifications as the code before this change, and byte-identical snapshots in every cycle
  without carry-over or marking. A differential comparison over 6,000 generated inputs with
  malformed lists, markers and sections raised no exception, modified no input and changed nothing
  outside `subdomains` and `email_auth.dkim`. Of 17 mutants of the independent verification 11 are
  killed; the 6 that survive need a forged `/dns` response or a corrupted snapshot to be reached,
  and the code behaves correctly there. Weight: at most 25 subdomain and 18 selector entries in a
  partial cycle; on a measured total failure with 25 active subdomains the markers add 2,627 bytes,
  and nothing accumulates over consecutive failures because they are rebuilt. Six existing tests, 11
  items, in `tests/test_orchestrator.py` and `tests/test_col02_chain.py` change; with their previous
  text they are the only 11 failures of the 907 tests of the two files on this change. One pinned
  the choice not to carry subdomains and DKIM, and pins instead that the `unknown` lists and the
  counts are those of the cycle and that no name is invented. Five compared the section kept on a
  total failure with the previous one minus the marker of the parts; they also leave out the two
  section markers, and every other key is compared. All of them pass on the code before this change
  as well. Suite with the parallel driver: 3,858 tests collected and 3,858 run, 3,857 passed and 1
  skipped, in 66.5 and 68.2 s, against 3,754 tests in 60.4 to 63.5 s on the code before this change.
  ruff reports 0 violations. Nothing was measured on production data. **Release condition.** The
  dashboard does not read the new markers or the lists of undetermined names: with this change alone
  it shows a carried subdomain or selector as current, with no sign and no date. This change must be
  released together with the dashboard change that displays carried and undetermined names, which is
  `CODE-74`. **Accepted and declared risks.** (1) No expiry: a zone that stays silent keeps
  a name carried, marked and dated, and its `observed_at` never advances. Making a name disappear
  takes a real negative answer. The stale-data alert of the base record types (`dns_stale_*`, after
  72 h) does not cover names, so the date in the marker is the only sign of age. (2) A name whose A
  query answers "no such name" or "no data" while its CNAME query does not answer is carried, marked
  and dated: the per-name status of `/dns` reports it as undetermined. (3) A carried name is listed
  both in `active` and in `unknown`, or in `selectors_found` and in `selectors_unknown`; a reader
  that adds the two lists counts it twice, which concerns the raw JSON and the downloadable JSON
  report. **Tracked separately**, all present before this change: a deep-copy recursion limit in the
  carry-over of the base record types, which stops the save of the snapshot when a base type is
  undetermined and the section of the cycle holds a value nested more than about 500 levels deep; a
  loss of the subdomain and DKIM observations of a cycle in which only the base types of the apex
  fail, to which this change adds the marker; and a crash of the dashboard's Intel tab on malformed
  snapshots. **Declared limit.** The tests and the times come from a development machine with Python
  3.13, not from the Docker harness of the project or the container.
- **With a DNS resolver that did not answer, `/dns` ran for about 380 s while the orchestrator gave
  up after 45 s, and the abandoned request kept a worker thread and up to 10 `dig` processes busy
  for another 335 s (`SEC-29`).** `dns_check` (`services/dns_intel.py`) runs its queries in 19
  serial stages: the 7 base record types one after the other, DMARC, DKIM in rounds of 8 selectors,
  BIMI, CAA, and the 25 subdomains in rounds of 10, A then CNAME. `dig_lookup` (`shared/utils.py`)
  lets each query run for up to `DNS_TIMEOUT + 10` s, 20 s with the default `DNS_TIMEOUT` of 10, and
  nothing bounded the time of the whole request. Measured with the real `dig` 9.18.39 and the real
  handler, in a network namespace with only the loopback interface and a resolver that never
  answers: the request of the orchestrator (`full=true&subdomains=true`, 18 DKIM selectors) took
  380.45 s, and 400.45 s with the 32 selectors a caller may ask for. The orchestrator received
  `None` at 45.3 s and had no DNS intel for that cycle, while the handler went on for another 335 s
  with one worker thread of the shared pool and on average 4.5, at most 10, `dig` processes, and
  sent 156 packets to the resolver. A healthy resolver answering every query in 3 s gave a complete
  result after 57.5 s, which the orchestrator lost as well; with two silent base types and every
  other answer fast, the base types after the second silent one arrived only after 40 s. **What
  changes.** `services/dns_intel.py` (19 lines added, 6 removed) and `shared/utils.py` (10 added, 3
  removed); standard library only. Each request to `/dns` has a deadline of 40 s, `DNS_DEADLINE_S`,
  read when the request starts and fixed for that request. Every `dig` receives only the time left
  to the request and is killed when the deadline passes, and after the deadline no query starts. A
  query that is not reached or is killed takes the `unknown` branch that already exists for a query
  without an answer (`RES-01`): records `[]` with status `unknown`, never "no record" and never left
  out of the response. The records obtained before the deadline stay in the response as data of this
  request. When all 7 base types are `unknown`, `error` is set as before, so the orchestrator reads
  the module as failed. The 7 base record types are queried in parallel, so two silent types cannot
  use up the deadline of the others; the keys of `records` and `records_status` keep their order. At
  most 10 `dig` processes run at once for one request, as before: 7 in the base stage, 8 for DKIM,
  10 for the subdomains. `dig_lookup` gains a keyword-only `limit`, the maximum time in seconds of
  the whole call. Without it the behaviour is unchanged (`timeout + 10`). With it the process lives
  at most `min(timeout + 10, limit)`, and with no time left (`limit` zero, negative or NaN) no
  process starts and the query is `unknown`. `limit` never reaches the argv: `+time` and `+tries=2`
  stay the integers they were, because `dig` rejects a fractional `+time` and exits without
  querying. The name guard of `SEC-26` runs first as before, and `/dns` is the only caller of
  `dig_lookup`. No endpoint, trust zone, dependency, port, `Dockerfile`, SQLite schema or persisted
  format is touched, so a rollback restores the previous code with no migration. **Measured.** With the real
  `dig` and handler and the orchestrator's real client, against a resolver that never answers, the
  handler returns after 40.03 s. At 40.27 s the orchestrator receives a result with every part
  `unknown` and `error` set, instead of `None`. The resolver receives 16 packets instead of 156, and
  no `dig` process is alive when the response leaves or 0.3 s later; with two silent nameservers,
  40.03 s and 17 packets. With 40 concurrent silent requests and eight busy processes on four CPUs
  the handlers return within 40.28 to 40.63 s and the client within 40.81 s; a single `dig` outlives
  its limit by at most 0.044 s. A slow but healthy resolver gives the complete result, faster than
  before because the base types run together: 6.8 s instead of 9.9 s at 0.5 s per query, 13.3 s
  instead of 19.5 s at 1 s, 26.3 s instead of 38.4 s at 2 s, 28.9 s instead of 42.2 s at 2.2 s, and
  39.3 s at 3 s, where the code before this change took 57.5 s and lost the result. The result is
  complete up to about 3.05 s per query, where before it was lost entirely above about 2.34 s; at
  3.1 and 3.5 s per query only the subdomains are cut. With latency drawn from an exponential
  distribution of mean 2 s, 5 of 6 runs are complete in 25.7 to 40.0 s and one has only its
  subdomains `unknown`; before, the runs took 30.6 to 50.8 s and 2 of 6 were lost. Down the real
  chain (orchestrator, intel store, classifier) with a healthy baseline, six scenarios of silent or
  partial results gave 0 alerts in every cycle. The parts answered in time are fresh in the snapshot
  and decide the classification, which is that of the healthy cycle unless the A record itself is
  cut. The cut record types and the SPF, DMARC, BIMI and CAA sections are carried over from the
  previous cycle. 74 tests sit in a module of their own, `tests/test_dns_deadline_sec29.py` (1,282
  lines), with a fake `dig` first in the `PATH` and a guard that refuses any other `dig`, so no real
  query is made and no network is used. On the code before this change 58 fail and 16 pass. The 16
  are controls: the shape of a cut part is the one a fast SERVFAIL gives, a healthy DNS gives the
  same body, key order and queries, the peak stays at 10, and the chain raises no alert and keeps
  the previous value of the cut parts. The other tests pin the response within 1 s of the deadline,
  a silent query that starts late in the request, the limit of each process at
  `min(timeout + 10, limit)`, the 7 base types starting together, no process or thread left after
  the response, one deadline per request, and the downstream chain. The module takes about 44 s on
  its own. Of 31 mutants of the test author and of the independent verification, 28 are killed and 2
  are equivalent. One survives: it computes the time left once per pool instead of once per query.
  That is a gap in the tests, tracked separately; the code computes the time left in one place.
  Suite with the parallel driver: 3,754 tests collected and 3,754 run, 3,753 passed and 1 skipped,
  in 60.4 and 63.5 s, against 3,680 tests in 52.5 s on the code before this change. No existing test
  changes outcome, and ruff reports 0 violations. Nothing was measured on production data.
  **Accepted and declared risks.** (1) Whoever controls the DNS of a lookalike can make two names in
  different serial stages never answer, for instance the AAAA record and `_dmarc`. `/dns` then stops
  at 40 s, and the stages after the second silent name come back `unknown`: BIMI, CAA, the DKIM
  selectors without an answer and the subdomains. Before, those parts could arrive with a response
  at about 44 s. No false alert follows, and no classification or severity changes (18 classifier
  profiles of 18). The dashboard shows only the active subdomains and the selectors found, though,
  so its list of subdomains can look empty; the display of undetermined subdomains and selectors is
  covered by `COL-31` and `CODE-74`. (2) A first cycle with a silent resolver stores a result with every part
  `unknown` instead of nothing. When the DNS comes back, one-time alerts appear for the parts that
  differ from that cycle, as they already did after a resolver that fails fast. (3) A first cycle
  with a partial result gives a one-time alert for each cut part at its first known value. (4) A
  slow domain whose A, MX and NS arrive within the deadline gets the classification of its data
  instead of `insufficient_data`. The severity is never below that of the complete data: lower than
  before for some domains, higher for others, such as a recent mail-only domain whose other record
  types are silent, which goes to `suspicious` HIGH. (5) A domain that is always slow can have more
  parts that stay `unknown` at every cycle. With a known baseline they are carried over and flagged
  as stale after 72 h, as before; a part never known gives no signal. (6) The 40 s are a constant,
  not tied at runtime to the `SERVICE_TIMEOUT` of the orchestrator (45 s by default). With
  `SERVICE_TIMEOUT` at 30 the orchestrator gives up at 30.3 s, as before, while the handler stops at
  40 s. (7) With `full=false` each request starts up to 7 `dig` processes at once instead of 1, so
  40 concurrent requests reach 280 processes instead of 40. That stays within the absolute peak of
  10 per request, 400 with the 40 workers of the pool, which the subdomain stage already reached.
  The process-wide cap is tracked separately. **Declared limit.** (a) The deadline starts when the
  handler runs. The wait for a free worker thread before it is not covered, and is tracked
  separately with the process-wide cap. (b) Also tracked separately: a log line that tells queries
  cut by the deadline from queries without an answer, which the log counts together. And a quirk of
  `dig_lookup`: with a non-integer `timeout` it starts a `dig` that exits without querying. The
  quirk is latent, because every caller passes an integer and the time left never reaches `+time`.
  (c) The times come from a development machine with Python 3.13, not from the Docker harness of the
  project or the container. The resolver of the container was not observed: if it answers SERVFAIL
  instead of staying silent, a silent name costs less than 20 s.
- **A lookalike domain could hide from HTTP monitoring with a page of about 4.3 KB: a decimal
  character reference with more digits than `int()` accepts made the analysis of the page raise, and
  `/http` answered 500 for all four URLs of the domain (`SEC-50`).** `detect_hidden_elements`
  (`shared/utils.py`) reads the page with `_TagCollector`, a subclass of `html.parser.HTMLParser`,
  which decodes character references in text and in attribute values with `html.unescape`. For a
  decimal reference (`&#` followed by digits) the standard library converts the digits with `int()`,
  which raises `ValueError` beyond `sys.get_int_max_str_digits()` digits, 4300 unless the process
  changes it, leading zeros included; hexadecimal references have no such limit. The error left the
  parser from text with or without `;`, from attribute values of any tag, quoted or not, from the
  content of `iframe`, `textarea`, `title` and `noscript`, and from the final branch of `close()`
  that reads the tail of the document: 23 of 45 contexts of the tokenizer, the same on Python
  3.11.17, 3.12.3, 3.13.16 and 3.14.5, with the bounded parser of `SEC-48` and with its fallback.
  The smallest such page is `&#` and 4,301 digits (4,303 bytes), and `/http` answered 500 even when
  only one of the four URLs served it. Without HTTP intel the risk of the domain went down instead
  of up, with no alert: measured on the real service in a lab, with built intel, a domain 20 days
  old with a hidden form went from HIGH to MEDIUM, with a rationale of no content, and one about 11
  years old from MEDIUM to LOW. **What changes.** Only `shared/utils.py` (74 lines added, 0
  removed); standard library only. Inside `_TagCollector` only, decimal references of 8 or more
  digits are shortened before the standard library decodes them: the leading zeros are stripped (`0`
  if all of them are zeros), and a value with more than 7 significant digits, always above U+10FFFF
  (1114111), becomes 1114112, which the standard library maps to U+FFFD. `int()` therefore receives
  at most 7 decimal digits, and the boundaries of every reference, the buffer and the source text of
  the tags do not change. The result is that of the standard library without a digit limit, which
  decodes leading zeros and values beyond U+10FFFF as a browser does: `&#000…65;` is `A`, a value
  beyond U+10FFFF is U+FFFD. `goahead` (text and tail of the document) and `parse_starttag`
  (attribute values) of `_TagCollector` run the interpreter's own code with a copy of their globals
  in which `unescape`, and `_unescape_attrvalue` where it exists (as on Python 3.13 and later),
  shorten first and then call `html.unescape`. Nothing changes for the rest of the process: the
  limit of `int()` is never set, and `html`, `html.parser`, `_markupbase`, `HTMLParser` and any
  other subclass keep the stock objects. The shortening is installed after the bounded parser of
  `SEC-48` and independently of it, so it covers that parser's fallback as well. It rests on
  internals of `html.parser` that are not public, so it is installed only if both methods exist as
  functions, read `unescape` or `_unescape_attrvalue` as global names, and these decode through
  `html.unescape`; otherwise both standard methods stay, never one shortened beside one standard,
  the import does not raise, a warning is logged and `_CHARREF_FALLBACK` holds the reason. The check
  costs about 3 ms, once at import. No endpoint, trust zone, dependency, port, `Dockerfile`, SQLite
  schema or persisted format is touched, so a rollback restores the previous code with no migration.
  **Measured.** 130 tests in a module of their own, `tests/test_html_charref_digits_sec50.py` (1,247
  lines). On the code before this change 90 fail and 40 pass on Python 3.13, and 73 fail, 40 pass
  and 17 are skipped on 3.12.3 (the 16 of `/http`, which need FastAPI, and one variant that does not
  apply there); the 40 are non-regression guards. The oracle is the standard parser with the limit
  of `int()` lifted for its own parsing only and then restored. `/http` answers 200 and analyses the
  four URLs with the hidden elements the oracle gives, in 14 contexts, with one hostile URL out of
  four, and on a page as large as the download cap of 2 MiB. In an interpreter at the minimum limit
  of 640 digits, with the code reading no limit, pages of 2 MiB with a reference almost as long as
  the page are read without error, so no conversion receives the digits of a whole reference.
  Further tests pin the position of the reference in a long text or value, the values of Chromium
  141 measured offline, the fallback of `SEC-48`, other limits of the process, the absence of any
  process-wide change, and the guard on changed internals. Same results: 0 differences from the
  standard library without a digit limit in parser events and collected tags over 107,228 documents,
  and in decoded values over 606,900 strings, on Python 3.11.17, 3.12.3, 3.13.16 and 3.14.5, with
  the bounded parser and with its fallback; 0 differences from the code before this change over the
  9,887 documents of a corpus of 10,392 that it reads without error, and none of the other 505 still
  raises. Against Chromium 141 on 31 cases the code gives the value of the standard library without
  limit in 31 and that of the browser in 30; the remaining case is a non-character (`&#01114111;`)
  that the standard library drops at any length, as it drops some controls such as U+0001, a
  difference that predates this change. Every mutant of the test author and of the independent
  verification is killed except a few that are equivalent or remove a guard check made redundant by
  another; a few die on only one of 3.12 and 3.13. Suite with the parallel driver: 3,680 tests
  collected and 3,680 run, 3,679 passed and 1 skipped, in 55.3 s; 0 ruff violations. **Cost.**
  Linear in the size of the page: from 256 KiB to 2 MiB the time grows 7.9 to 8.4 times on every
  form, and the longest pause stays that of `html.unescape` of the standard library, at most 60 ms.
  A normal page of 2 MiB costs about 3.5 % more; the worst case, a page made only of 8-digit
  references, costs up to about 40 % more (40 to 43 %, 75 to 80 ms at 2 MiB). Peak memory stays
  linear; on pages dense with 8-digit references it grows by about 12 MiB at 2 MiB, below the worst
  existing form. Nothing was measured on production data. **After release.** Domains whose `/http`
  failed get a real analysis on the first cycle, so alerts for hidden elements may appear for them:
  the expected recovery of their HTTP monitoring, not a regression. **Declared limit.** (a) The
  suite ran on Python 3.13 and the module on 3.12.3 as well; the shortening was also checked on
  3.11.17 and 3.14.5, not on the interpreter of the image, where the warning at import and
  `_CHARREF_FALLBACK` show whether it is active. (b) Tracked separately: the failure of the whole
  request for one URL and the signalling of a failed analysis to the classifier; a parser exception
  on older interpreters; a static install check that does not see a change to a single decoding
  point; a quirk in the parsing of dimensions; the missing logging of 500 answers from the services.
  (c) The times come from a development machine with Python 3.13, not from the Docker harness of the
  project or the container.
- **A page served by a lookalike domain could stop the whole process of the service for seconds: the
  HTML parser of the standard library, which `/http` ran three times on every body, holds the
  interpreter lock for the whole length of a tag with many attributes or many spaces, and the
  analysis turn of `SEC-47` let several bodies be analysed at once after a wait of 5 s (`SEC-48`).**
  `detect_hidden_elements` (`shared/utils.py`) reads forms, iframes, tracking pixels and dead markup
  with `_TagCollector`, a subclass of `html.parser.HTMLParser`, and parsed each body three times,
  once per set of tags. Three regular expressions inside that parser, `locatetagend`,
  `tagfind_tolerant` and `attrfind_tolerant`, repeat a compound group, which `re` runs in one C call
  that pushes a frame on its own stack for each repetition: one per attribute of a tag, one per
  space or `/` after the name of a tag or after an attribute. A tag with many attributes or many
  spaces, closed or not, therefore makes one C call as long as the tag, which holds the interpreter
  lock and allocates 50 to 230 bytes per byte of the tag; on a tag that never closes `close()`
  repeats the scan, so a body made six such scans. At 2 MiB, the cap of a download, each call took
  0.23 to 0.40 s on an idle machine and up to 2.09 s with eight busy processes on four CPUs, and one
  body took the process to 370-466 MB of resident memory. On a real process under uvicorn one
  hostile page of 2 MiB (`<a b b …`) left the health probe, the dashboard and the login unanswered
  for up to 2.19 s, and four such pages at once for 7.39 and 8.64 s in two runs, while `/http` took
  35.8 to 45.2 s against the 45 s timeout of the orchestrator. With only the parser fixed, four
  concurrent pages of `<a b b …` kept the probes at 1.74 s against 1.02 s for the same code with a
  parser of zero cost (medians of 10 runs), because of the turn of `SEC-47`: a body waited for the
  turn at most `ANALYSIS_MAX_WAIT_S` (5 s) and was then analysed anyway, so of the 16 bodies (about
  0.9 s of CPU each) 5 to 8 ran out the wait and were analysed side by side, up to four besides the
  holder of the turn, and the probes queued for the lock behind the long C calls of one thread after
  another. **What changes.** `shared/utils.py` (153 lines added, 31 removed) and
  `services/http_fingerprint.py` (93 added, 43 removed); standard library only. **A parser of
  bounded cost, same results.** At import `_TagCollector` receives its own
  `check_for_whole_start_tag`, `parse_starttag` and `parse_endtag`: the code objects of the running
  interpreter, bound to a copy of the globals of `html.parser` in which the three expressions are
  replaced. `locatetagend` becomes a scanner that reads at most 256 attributes per C call and loops
  in Python between blocks, where the lock is released: each block resumes from the last attribute
  read and stops where the whole repetition would, and a `>` captured in the first block ends a
  normal tag in one call. The trailing repetition of `tagfind_tolerant` and `attrfind_tolerant`
  becomes an equivalent tail that reads the whole run of spaces and `/` with a character class,
  without the final `/` when a `>` follows it. Since the code is the interpreter's own, so is the
  decoding of attribute values, which differs between versions of Python. Nothing in `html.parser`
  is replaced for the rest of the process: the module, `HTMLParser` and any other subclass keep the
  stock objects. The replacement applies only if each method exists and reads the expected names, if
  each expression has exactly the text and flags copied from the standard library, and if two probe
  pages, one of them crossing the boundary between two blocks, give the tags of the stock `feed` +
  `close`; otherwise `_TagCollector` keeps the stock parser, slow on such tags but with the same
  results, a warning is logged at import and `_HTML_PARSER_FALLBACK` holds the reason. **One parsing
  per body.** One collector reads forms, iframes, images and dead markup, and each list filters it
  by name; the body is assigned to the buffer of the parser and read with a single `close()`, where
  `feed()` + `close()` would read a tag that never closes twice. `_collect_tags`, left without
  callers, is removed. **A strict analysis turn.** It replaces the rule of `SEC-47` that a body
  waits at most `ANALYSIS_MAX_WAIT_S` (5 s) and is then analysed anyway; the constant is removed.
  One body is analysed at a time in the whole process, however long the others wait. Among waiting
  bodies the shortest goes first, and between equal lengths the first to arrive; a body that has
  waited more than `ANALYSIS_AGING_S` (10 s) goes before every body that arrived after it, so a body
  waits at most 10 s plus the analyses of the bodies that were ahead of it when it arrived. While a
  body of one `/http` is in analysis no other body of the same request receives the turn, whether
  the turn falls free, is passed on or is given by the safety valve, and when that body ends a free
  turn goes at once to the next body designated; this replaces the lock per request of `SEC-47`.
  Safety valve: a turn held for more than `ANALYSIS_STUCK_S` (60 s) can only come from a defect,
  since the analysis of a body of 2 MiB takes a few seconds; the waiting bodies check it every
  `ANALYSIS_STUCK_POLL_S` (1 s) and pass the turn to the body the usual order designates among the
  other requests, with one error in the log that carries no data of the page, and the stuck body, if
  it ever ends, has no turn left to pass on. As in `SEC-47` the turn is passed on in a `finally`, a
  wait that raises leaves neither the turn nor its place in the queue, and the download stays
  outside the turn. No endpoint, trust zone, dependency, port, `Dockerfile`, SQLite schema or
  persisted format is touched, and the results of the analysis are identical, so a rollback
  restores the previous code with no migration. **Measured.** 43 tests in a module of their own,
  `tests/test_html_parser_cost_sec48.py` (1,001 lines), and 26 tests of the turn in
  `tests/test_http_body_analysis_sec47.py` instead of 11 (163 tests in that module instead of 148):
  the six that pinned the wait of 5 s, its constant or the plain arrival order are rewritten or
  removed, each with its reason written down and reviewed by the independent verification; two
  comments of `tests/test_utils.py` name `_TagCollector` instead of the removed function. The memory
  tests read the peak of `tracemalloc` during an analysis, a count of bytes that does not depend on
  the load of the machine: on 17 hostile families the peak does not grow from 64 to 256 KiB (limit
  1 MiB of growth, where the stock parser grows by 4 to 45 MB), and a closed tag with thousands of
  attributes costs at most 256 bytes per attribute. On the code before this change 33 of the 206
  tests of the two modules fail (21 of the parser, 12 of the turn) and 173 pass: the rest of the
  `SEC-47` module, the comparisons with the stock parser, which that code uses, and the rules of the
  turn that it met as well. The longest C call of the parser over 15 hostile classes of 2 MiB is
  10.6 to 11.3 ms on Python 3.13 and 7.8 to 12.9 ms on 3.12 over four measurements, against 111 to
  393 ms and 121 to 363 ms on the code before this change. The analysis of a body costs less CPU:
  0.19 s instead of 1.97 s on 2 MiB of `<a b b …`, 0.71 s instead of 2.56 s on a closed `<a b=c …>`
  tag of 2 MiB, 0.53 s instead of 1.01 s on a readable page of 1.4 MiB; the peak of memory on 2 MiB
  of `<img>` tags is 138.7 MiB instead of 281.0 MiB. Same results: 0 differences in parser events
  and collected tags against the stock parser over 46,251 documents on Python 3.11.17, 3.12.3,
  3.13.16 and 3.14.5; 0 differences in the output of `detect_hidden_elements` against the code
  before this change over 46,262 documents on 3.12 and 3.13, so the fields that feed the classifier,
  its alerts and its verdicts do not change; the replaced expressions give the same match on every
  string of up to 6 characters over 14 symbols of their grammar (8,108,731 strings on 3.13, up to 5
  characters on 3.12) and on 300,000 random strings per interpreter; the security review found 0
  differences over about 250,000 comparisons aimed at the boundaries between blocks, the closing of
  script, style and similar elements, and documents cut short. On a real process under uvicorn, with
  a fake site on the loopback interface serving a different body on every URL, the acceptance
  criterion compared the longest wait of the health probe, the dashboard and the login with the same
  code running a parser of zero cost, alternating 3 runs of each per row: on 9 hostile classes with
  one page the medians differ by −0.09 to +0.06 s (limit +0.15 s), and on 4 classes with four
  concurrent pages by −0.45 to +0.01 s (limit +0.30 s); in absolute terms the medians are 0.29 to
  0.54 s with one page and 0.44 to 0.67 s with four. Two more rows of four pages, a closed tag of
  2 MiB with many attributes and dense `<p>` markup, are within the floor as well. The independent
  verification measured −0.20 to +0.10 s with one page and −0.20 to −0.01 s with four, and −0.12 to
  −0.04 s with four pages on the final version of the turn. A page of normal size queued behind four
  hostile pages finished its `/http` in 0.94 s, against 5.46 s with the turn of `SEC-47` and the
  same parser. Under load with injected failures (3 runs of 600 threads; 6 runs of 334 to 365 bodies
  in requests of 1, 2 and 4 bodies, three of them with the stuck time lowered to 30 ms so that the
  valve fires) two bodies of one request were never in analysis together, there was never more than
  one analysis at a time without the valve, and the turn and the queue ended free. Of the 27 mutants
  of the last full round of verification 25 are killed, one of them by a test added after that round
  and one only because the module then hangs, and 2 are equivalent. Suite with the parallel driver:
  3,550 tests collected and 3,550 run, 3,549 passed and 1 skipped, in 53.0 and 53.7 s, against 3,492
  tests in 35.7 to 40.6 s before this change; 0 ruff violations. Nothing was measured on production
  data. **Declared limit**: (a) The price of the bound on the wait: under sustained load from many
  concurrent callers of `/http` the queue ages and is served in arrival order, and a page of normal
  size waits for the whole backlog ahead of it. With a stream of dense pages of 512 KiB, one `/http`
  every 1.5 s, a normal page waited 35.4 and 36.0 s, against 10.2 and 9.7 s with the turn of
  `SEC-47`; in bursts it is the other way round (0.94 s against 5.46 s, above). The pipeline sends
  one domain at a time, so this takes many callers of `/http` besides it. (b) A body given the turn
  whose thread stays suspended for more than 60 s, for example in a stopped process, is passed by
  the valve and may then be analysed beside whichever body holds the turn after it, never beside a
  body of its own request. (c) The bounded parser rests on internals of `html.parser` that are not
  public; on an interpreter where they differ the stock parser stays, with the same results and its
  cost per tag. The suite ran on Python 3.13; the parser was also checked on 3.11.17, 3.12.3 and
  3.14.5, not on the interpreter of the image. (d) Tracked separately: the remaining whole-page
  scans of the analysis, which set the floor of these measurements; the throughput of `/http` with
  several very large dense pages at once; the visibility of the fallback; differences between
  interpreters; memory per body; the signalling of a failed analysis; and a parser exception on a
  crafted input. (e) The times come from a development machine with 4 CPUs, Python 3.13 and fake
  servers on the loopback interface, not from the Docker harness of the project or the container.
- **The suite took 89 to 94 s in one process (3,423 tests), over the project limit of 90 s, and
  could not be split across processes without adding a dependency (`BUILD-09`).** Every WHOIS lookup
  of the tests starts a child process (`SEC-35`, about 66 ms each), which took the serial run from
  63.8 s to 74-80 s, and every fix adds tests. `pytest-xdist` would split it, but the project adds
  no dependency without approval. **What changes.** Only `tests/` (1,527 lines added, 28 removed;
  standard library only, Python 3.11 or later for `process_group`): no served code, image (the
  `Dockerfile` does not copy `tests/`), dependency or workflow. (1) A hook in `tests/conftest.py`:
  with `DS_TEST_SHARD=k/n` a pytest process collects the whole suite and runs only part k of n. It
  splits by group, not by test: the outermost class, because its tests share state, or the whole
  module when it has a module-level setup or teardown, which must run once. The part of a group is
  the crc32 of its node id modulo n, the same in every interpreter, where `hash()` changes with the
  seed; the choice comes after `-k`, `-m` and `--deselect`. Unset or empty, nothing changes; a
  malformed value stops the session instead of running the whole suite in every process. In a part,
  SIGTERM and SIGHUP at their default disposition become `KeyboardInterrupt`, so pytest runs the
  teardowns. Each process writes the tests it collected and the ones it ran, with their outcome, to
  `DS_TEST_SHARD_REPORT`. (2) A driver, `python tests/run_parallel.py -n N [pytest arguments]`,
  starts the N parts together, each with its own `CASES_DB`, `FEED_DATA`, `INTEL_DIR`, `EVENTS_DIR`,
  `--basetemp` and `TMPDIR` inside one temporary directory. Exit codes are not enough, because a
  test that no part runs leaves every process at 0: the driver fails if a part fails, if a part ends
  without a well-formed report, if the parts collected different suites, if a collected test did not
  run or ran more than once, or if no test was selected; `--collect-only` is a usage error. Each
  part leads its own process group, with standard input from `/dev/null`. At every exit, and on
  SIGTERM, SIGHUP or SIGINT (exit 128 + the signal), every group gets SIGTERM, what is left after
  one second of grace gets SIGKILL, and the directory is removed with one retry. A signal during the
  start of a part, the stop or the removal waits for the end of that step, and one that the driver
  receives already ignored (`nohup`) stays ignored. If the directory does not go away, the driver
  prints its path and fails. (3) 69 tests in `tests/test_run_parallel.py` pin those guarantees on
  generated mini-suites, never on the real one, by recording what each process saw and ran. At most
  4 processes started by that module are alive at once. An intermittent red under the driver (1 in
  36 runs) came from there: the module started about 42 interpreters together, and with 38 to 40
  runnable processes on 4 CPUs a test of the download deadline of `http_get_with_retry`, in another
  part, waited in the run queue of the scheduler until its 0.5 s deadline fired. Reproduced outside
  the driver under 43 busy processes: 4 red out of 400, the deadline firing at 505-576 ms with 5-6
  ms of CPU used. With the cap the runnable processes stay at 16-17, and that request chain, 206-214
  ms on an idle machine, peaks at 244-262 ms instead of 288-392 ms; the module costs 0.1 to 1.4 s
  more. (4) Two existing tests measured a ratio of costs in a way that contention could push over
  the threshold. The linear-scaling test of `detect_hidden_elements` on nested closed iframes
  (`tests/test_utils.py`, 2,000 against 8,000, ratio below 6) measured wall-clock time, all the
  small runs first and then all the large ones. It measures the CPU time of the thread, with the two
  sizes alternated and the minimum of 3 for each. On the code under test, under bursts of processes,
  the wall-clock ratio ranged from 1.55 to 10.67 (6 of 30 over 6) and the revised one from 3.60 to
  4.90; two quadratic variants of the code stay red 5 times out of 5, at 10.30-12.39 and
  14.24-15.46. The linear-cost test of `SEC-47` (`tests/test_http_body_analysis_sec47.py`) already
  measured CPU time in a separate interpreter, but on a shared virtual machine the CPU time of a
  thread inflates in stretches, up to about 3 times and for up to about 180 ms, longer than the
  three attempts of the test (about 120 ms); it went red once under the driver, at 8.03 against a
  limit of 8.0. A ratio over the threshold is measured again for up to 3 s, in 3 alternated pairs
  per attempt, keeping the minimum for each size; sizes, threshold and budget do not change. Process
  load did not reproduce that red (0 in 5,300 calls); a model of the stretches injected into the
  measuring interpreter did (11 red calls out of 400 before, 0 after; 6 red cases out of 871 for the
  whole class before, 0 after), so this evidence is indirect. The test loses no power: on the
  quadratic code that `SEC-47` replaced both versions give the same 36 red cases, and a super-linear
  mutant is red in 18 cases against 17, the 17 included; the retries cost time only when a ratio is
  over the threshold. **Measured**: with the driver at `-n 4`, 16 runs out of 16 green, each with
  3,492 tests collected and 3,492 run (3,491 passed, 1 skipped), in 35.7 to 40.6 s; after each, no
  leftover directory and no process alive. In one process the same 3,492 tests pass in 90.65 and
  102.18 s over two runs, about 11 s of which are the 69 tests of the driver. The serial run stays
  in CI, unchanged, as the check that no test depends on the order or on the other parts. 0 ruff. A
  SIGTERM to the driver on the real suite at 3 to 32 s: exit 143 in 0.83 to 1.12 s, no process
  alive, directory gone; 170 signals during the start of the parts left no orphan, and 250 at random
  instants no leftover. Independent verification by mutation of the driver and the hook: 19 of 29
  mutants killed, 3 equivalent, 7 surviving (point g). **Declared limit**: (a)
  `tests/test_feed_manager.py` sets `FEED_DATA` to a fixed path at import, and some tests there and
  in `tests/test_case_manager.py` use other fixed paths, so two drivers, or a driver and a serial
  run, started together can collide. (b) No time limit per process: a hung part holds the driver
  until it is interrupted. (c) A process that a test detaches into its own session or group and does
  not stop in a teardown outlives the driver, and a teardown longer than the second of grace is cut
  short by SIGKILL. (d) The parts are in their own groups, so a SIGKILL to the driver or to its
  group does not reach them: they stay alive, and so does the directory; the driver is stopped from
  outside with SIGTERM, SIGHUP or SIGINT. (e) `main` installs signal handlers, so it must be called
  from the main thread. (f) The tests of processes and signals read `/proc` and run on Linux only.
  (g) The 7 surviving mutants are branches of the driver and the hook with no test, among them the
  check on the removal (if it regressed, a directory left behind would give exit 0); another test of
  the download deadline went red once in 40 driver runs before the cap and in none of the 16 after,
  and its cause is unverified. Both are tracked separately. (h) The times come from a development
  machine without Docker, with Python 3.13, 4 CPUs and `node` on the path, not from the Docker
  harness of the project or a hosted runner.
- **A page served by a lookalike domain could stop the whole process of the service for minutes: the
  analysis of the body in `/http` ran backtracking regular expressions that reread the body to its
  end from every repeated opening that is never closed, and they hold the interpreter lock while
  they run; the pipeline visits that page by itself (`SEC-47`).** `/http` downloads up to four pages
  of a domain and analyses each body with `normalize_html_for_fingerprint`, `extract_visible_text`,
  `detect_suspicious_patterns` and `detect_hidden_elements` (`shared/utils.py`) and with the
  extraction of the title (`services/http_fingerprint.py`). Whoever controls the domain chooses the
  body, and the pipeline fetches the pages of every lookalike it monitors, so no request from
  outside is needed. The investigation found 16 distinct patterns in 19 places, in four families: an
  opening followed by a lazy `.*?` and a closing (`<script>`, `<style>`, `<!--`, `<title>`, and the
  content of scripts and comments); `<[^>]+>` on a `<` with no `>`; an opening followed by an
  unanchored `[^>]*` and a word looked for further on (`<form … action`, `<input … type=password` or
  `email`, hidden inputs, meta refresh, hidden divs); and `data:[^;]+;base64,`. On a body with many
  openings and no closing each of them rereads the body from every opening: a quadratic cost, cubic
  for the hidden inputs, the meta refresh and the hidden divs, whose patterns have two `[^>]*`. `re`
  does not release the interpreter lock, so while one of them runs every other thread of the process
  stops. Measured on the previous code: `normalize_html_for_fingerprint` took 2.5 s on 64 KiB of
  repeated `<script>` and did not end in 330 s at 2 MiB, the cap of a download;
  `detect_hidden_elements` took 7.7 s on 16 KiB of repeated `<meta http-equiv=refresh` and more than
  60 s on 32 KiB; on 62 KiB three of the functions took about 2.2 s each, with another thread
  stopped for 2.33 s. In the single-process deployment (`unified.py`) the health probe, the
  dashboard and the login are served by the same interpreter: a hostile page of 2 MiB of repeated
  `<script>` left them unanswered for the whole measurement (60 s), two other families for more than
  150 s, and a pipeline started on two domains, one of them serving 96 KiB of repeated `<script>`,
  took 67.0 s, stopped the health probe for 33.5 s and lost the HTTP intelligence of the hostile
  domain. The lists of `detect_hidden_elements` had no cap either: a page of 2 MiB of 1x1 images
  gave 95,325 tracking pixels and a JSON of 7.1 MB, which went into the response of `/http`, the
  snapshots and the requests between services. **What changes.** `shared/utils.py` (293 lines added,
  33 removed), `services/http_fingerprint.py` (84 added, 11 removed) and
  `services/dashboard_app.html` (4 added, 2 removed); standard library only. **Linear scans, same
  results.** Each of the 19 uses is replaced by a scan that passes over the body once and gives what
  the expression gave: the same matches, groups, positions and order. The replaced expression is
  written in the docstring of each helper. The scans rest on two facts: if there is no closing after
  one opening, there is none after the later openings either; and the openings that share the same
  first `>` after them have the same outcome. Words are still searched with `re` and `IGNORECASE`,
  not with `str.find` on lowered text, so characters such as `ſ` and `İ` match as they did in the
  original expressions. The title is read by a new `extract_title`. The scans of `<form … action`
  and `<input … type=…` are keyed by the exact patterns of `DEFAULT_SUSPICIOUS_PATTERNS`: any other
  pattern, or a changed one, still goes through `re.findall`. **One analysis at a time.** In `/http`
  the analysis of a body takes a turn shared by every request, in arrival order: the turn is handed
  straight to the oldest waiting body, and a body waits for it at most `ANALYSIS_MAX_WAIT_S` (5 s, a
  constant of the module read at every wait) and is then analysed anyway, so a slow page cannot hold
  up the pages of other domains for longer than that. The bodies of one request also take a turn of
  their own, with no limit, inside the shared one, so at most one body of a request is analysed at a
  time. The turn is passed on in a `finally`, and a wait that raises either passes on a turn that
  had just been handed to it or leaves the queue, so an error never leaves the turn taken. The
  download stays outside the turn. **Capped lists, totals of the whole page.** The nine lists of
  `detect_hidden_elements` keep their first 100 items, in document order, and only after the risk
  score and the `summary` have been computed on the whole page; for each list that was cut a new
  key, `truncated`, holds its total (`{list: total}`, integers only). A list of 100 items or fewer
  is unchanged and adds no `truncated`. The classifier raises the alert of injected content from the
  first hidden div with a form or an input: if that div lies beyond position 100 it takes the last
  place of the list, so the alert stays the one of the whole page, and no file of the classifier is
  touched. The Intel tab of the dashboard shows the total of the tracking pixels, through `esc()`,
  and a `… +N more` line under the 100 it lists. No endpoint, trust zone, dependency, port,
  `Dockerfile` or SQLite schema is touched; the functions changed in `shared/` are called only by
  `/http`. A rollback restores the previous code with no migration: the snapshots written with the cap stay
  readable by the previous code, which ignores `truncated`. **Measured.** 148 tests added in
  `tests/test_http_body_analysis_sec47.py` (1,569 lines), no existing test touched. The cost of each
  function is the CPU time of the calling thread, measured in a separate interpreter that is killed
  after 2.5 s, at 64 and 256 KiB on 20 hostile families, five of them with a single `>` at the end:
  a linear cost grows about 4 times, a quadratic one 16, and the limit is 8. A thread of the test
  process that wakes every 5 ms measures how long it is stopped while `/http` analyses a hostile
  body of a few KiB (limit 0.25 s). The turn is checked on the real handler behind `TestClient` with
  a fake site: arrival order, bounded wait, no wait without contention, never two bodies at once,
  the bodies of one request never together, a turn that survives an analysis or a wait that raises,
  and a turn handed over just as the wait runs out. The lists are checked at 100 and at 237 items,
  with totals, risk, `summary`, the alerts of the classifier, the verdict on a lookalike and the
  Intel tab rendered by the real script of the page in node; nine readable pages and a seeded corpus
  of 80 documents of mixed markup give the analysis fixed before this change. On the code before
  this change 64 of the 148 fail and 84 pass: the 84 are the controls, which are the families that a
  function already analysed in linear time, the lists of 100 items or fewer, the risk and the
  `summary` of the whole page, the choices of the replaced patterns, the alerts and the verdict, the
  readable pages and the corpus, and the checks of the turn that code with no turn passes as well.
  Independent verification: the comparison with the previous code gave 0 differences over 377,700
  documents (six seeds, Python 3.13 and 3.12) in the normalized form, the visible text, the title,
  the suspicious patterns and the hidden elements (equal below the cap, and checked against an
  independent model of the cap above it), and the same alerts and verdicts on about 88,000 documents
  with a risk above 0 or lists beyond the cap; a second comparison of about 174,000 documents (`ſ`,
  `İ`, `ı`, `K`, NEL, U+3000, entities, unbalanced quotes, `>` inside quoted values, partial
  closings) also gave 0 differences, so the canonical hash and the hash of the visible text of a
  page do not change at the first cycle after the deploy. Over 40 hostile families of 2 MiB the new
  scans take at most 2 s per body, `extract_title` at most 0.022 s, and another thread of the
  process is stopped for at most 0.26 s. On a real process under uvicorn with a fake site on the
  loopback interface, over 24 hostile families of 2 MiB, a normal page and a readable page of 2 MiB,
  every `/http` completed the analysis of its four URLs and the health probe, the dashboard and the
  login answered within 1.23 s at most over three rounds of verification; the readable page took
  12.1 s against 12.5 s before. The pipeline with the hostile page of 96 KiB took 0.27 s instead of
  67.0 s, with the health probe at 0.009 s and the HTTP intelligence of both domains. The responses
  of `/http` for the hostile families with long lists went from 10 to 27 MB to at most 112 kB. A
  normal page that arrives while a long page of 2 MiB is being analysed waits for the turn and
  finished in 5.15 s (0.55 s on the previous code, which had no turn). Of the 60 mutants of the last
  verification 53 were killed and the 7 survivors are equivalent or minor; the 10 non-equivalent
  mutants that survived the first version of the tests are killed. The module passes 5 times at rest
  (6.5 to 7.2 s) and 3 times with 8 processes using the CPU on 4 cores (14.2 to 16.4 s). Suite 3274
  to 3422 passed, 1 skipped, 0 failed, in 93.99 s, over the limit of 90 s (80.09 s before; the time
  budget of the suite is tracked separately); 0 ruff violations. Nothing was measured on production
  data. **Declared limit**: (a) The check was made with fake servers on the loopback interface and
  with pages rebuilt from real forms; no real page was captured. (b) The suite ran on Python 3.13;
  the equivalence with the previous code was also checked on 3.12.3, the minor version of the image,
  but the suite was not, and nothing was run in the Docker harness or in the container. (c) The cap
  of 100 and the wait of 5 s are not calibrated on real traffic: 100 is above the longest list
  measured on pages rebuilt from real forms (80 base64 blocks). (d) Other performance limits of the
  analysis of a body are tracked separately. (e) The times come from a development machine, not from
  the Docker harness of the project.
- **A long or hostile WHOIS reply could freeze the whole process of the service: the parsers of
  `python-whois` run super-linear regular expressions while they hold the interpreter lock, and
  the library sets no cap on the size of a reply, no deadline on a lookup as a whole and no end to
  the referral it repeats (`SEC-35`; found in the security review of `COL-17`).** The lookup reads
  text written by servers that the service does not control (the root server, the registry, the
  registrar), over port 43 and in clear, so a server in the chain or an attacker on the path can
  write it. `python-whois` 0.9.5 (the pinned version) interprets that text inside the process of
  the service, and `re` does not release the interpreter lock: while a regular expression runs,
  every other thread of the process stops. The investigation measured about a dozen such sources
  with the real library and fake servers: the search for email addresses on one long line with no
  `@` (8 KB about 1 s, 16 KB 3.6 s, 50 KB 36 s); the parser of `.eu`, cubic in the spaces after one
  field (1,600 bytes on one line about 20 s); the parser of `.hk`, quadratic in the size of the
  text (8 KB 13.8 s); the search for the registrar server in the reply of the registry (64 KB
  17.6 s) and for the `whois:` line in the reply of the root server (64 KB 20 s); the parsers of
  `.jp` and `.ee`; the concatenation of the reply in the read loop of the library (16 MB 12.8 s).
  Nothing bounded the exchange either: no cap on the bytes read; a timeout for each operation
  only, which a server that sends one byte every few seconds never trips, so the request stays
  open without limit; and a registry that answers `=xxx` to every request makes the library repeat
  it until `RecursionError` (991 connections in the test, 480 MB more with a 500 KB reply). In the
  single-process deployment (`unified.py`), where the same interpreter serves the other routers,
  one request for a domain with a hostile reply stopped the health probe, the dashboard and the
  login: measured on a real process under uvicorn, 8 KB stopped them for about 1 s and a `.eu`
  reply of 1,600 bytes for 19.7 s, longer than the 5 s that the health check of the container
  waits for an answer. **What changes.** Only `services/whois_intel.py`, 232 lines added and 2
  removed, standard library only. **The network stays in the process, with a budget.** `NICClient`
  is subclassed and only `get_socket` is overridden, delegating to the method of the library (its
  SOCKS setup and the fake sockets of the tests keep working). Every connection of a lookup,
  whether to the root server, the registry, the registrar or a repeated referral, goes through a
  socket that answers to one budget: a deadline of 15 s for the whole lookup (the timeout of each
  operation, `connect` included, is cut to the time that is left), at most 5 connections (the root
  server counts), at most 8 KB read from the root server and 8 KB from the registry, and at most
  64 KB in all (the registrar counts only in the total). At a byte cap the socket answers as at the
  end of the stream and the library keeps the text read: a truncation, not an error, so the fields
  in the first KB stay an observation. A deadline or a connection over the limit raises `OSError`,
  which the library treats as a network failure. The limits are constants of the module,
  read at each lookup and not settable from the environment. **The parsing moves to a child
  process.** `WhoisEntry.load` runs in a Python child (`-I -c`, so it ignores the `PYTHON*`
  variables and does not import from the working directory) started with `Popen` and
  `communicate(timeout=)`: the text (64 KB at most) goes in through stdin and a JSON with only the
  values that the service reads comes out (dates as ISO text). Before it reads its input the child
  sets `RLIMIT_CORE` to 0 (the default action of the CPU signal writes a core file that holds the
  text of the reply) and `RLIMIT_CPU` to 4 s with a hard limit one second above, and lowers its
  priority with `os.nice(10)`; a wall timeout of 8 s kills it and waits for it, so no zombie is
  left. The priority is fairness, not a barrier: if the system refuses it the child goes on, while
  a refused limit makes the lookup fail. From the environment the child receives only `PATH`,
  `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ` and `LD_LIBRARY_PATH`, and only the ones the service has: the
  credentials of the service are not in its environment. At most 4 children live together (a
  counter with a condition, read at each acquisition and freed on every outcome): a lookup that
  finds no free seat waits at most as long as the wall timeout and then answers with a fixed text
  (`WHOIS_PARSE_BUSY_ERROR`). That outcome depends on the load of the moment and not on the
  domain, so it is not saved in the cache. A child that cannot start, runs out of time, dies or
  writes a reply that cannot be read gives another fixed text (`WHOIS_PARSE_FAILED_ERROR`), never
  the text of the registry or the output of the child, with the shape of a failed lookup of
  `COL-17` (fields `None`, lists empty, `privacy_protected` false). An exception of the parser with
  a text of its own (`No match for …`) stays an error with that text: the child cuts it to 1,024
  characters and the service sanitizes and cuts it as before (200 characters and `...`), so the
  `error` of any exception is the same text as before. The call is what `whois_lib.whois(domain)`
  did, split in its two public steps (`NICClient.whois_lookup` for the text, `WhoisEntry.load` for
  the parsing), and the line that the library writes in its log when a network failure ends a
  lookup is the same. The guard of `COL-17`, the cache, the command branch and the shape of the
  response are untouched. No `shared/`, endpoint, trust zone, dependency, port, `Dockerfile` or
  SQLite schema is touched, and a rollback restores the previous code with no migration. **Measured.** 88
  tests added in `tests/test_whois_intel_sec35.py` (2,091 lines), no existing test touched. They
  run the real service and the real library with only `NICClient.get_socket` replaced by fake
  servers on a stream (no connection is opened, and a server the test does not expect fails it),
  with a second thread of the same process that wakes every 5 ms to measure for how long the
  others are stopped. The hostile replies are a long line in the record of the registrar, `.eu`
  with spaces after one field, `.hk` without the expected field, spaces after `Domain Name:` in
  the first hop and after `whois:` in the root answer, repeated `Domain Name:` lines, a parser
  exception with a text of 48 KB, floods of 700 KB from the root server, the registry and the
  registrar, `=xxx` loops with short and with long replies, and a server that drips one byte every
  half second. What a hostile reply costs is measured in seconds of CPU of the process and of its
  children, with a limit between what the service costs and what it would cost without the
  defense, because the wall time of the same regular expression changes with the load of the host:
  the `.eu` case 1.0 s of CPU with the limit of the child lowered to 1 s and about 5.0 s without
  it, the `.hk` case 1.0 and 4.4 s, the first hop 0.4 and 3.1 s. Typical readable replies (a thin
  `.com` record, one with a second hop and a legal text of 1.7 KB on one line, `.de`, `.it`, `.eu`,
  `.org`) give the same fields, dates included. On the code before this change 65 of the 88 fail
  and 23 pass: the 23 are the controls, which are the readable replies field by field, a domain
  unknown to the registry, an unreachable root server, the exceptions of the parser that keep
  their text and their sanitizing, the truncated replies that keep their first fields, the log
  line of the library and the seats that are freed after a success or an error of the parser.
  Independent verification: on a real process under uvicorn with fake servers, a `.eu` reply of
  1,600 bytes left the health probe, the dashboard and the login unanswered for 19.64 s before
  this change and for at most 0.01 s with it, and a reply of 8 MB took 26.2 s with another thread
  stopped for 22.7 s before, against 0.15 s and 0.01 s with it. The longest stop of another thread
  over 22 hostile scenarios was 0.39 s (the first hop alone stopped it for 2.4 to 3.2 s before).
  The comparison with the code before this change on 4,765 cases of readable replies gives 0
  differences in the fields. With a burst of hostile `.eu` lookups the children were 40 and 594 MB
  without the cap and 4 and 60 MB with it; 12 hostile lookups in the real service left 0 zombies
  and no seat occupied, 200 timeouts left no descriptor open and no zombie, and the seats were
  freed on seven simulated outcomes (success, expiry, interruption, `OSError`, a JSON that cannot
  be read, a `Popen` that raises `OSError` or `TypeError`). The child imported nothing from a
  hostile `json.py`, `sitecustomize` or `PYTHONSTARTUP`, none of the credentials named in the
  compose files reaches it, and every connection of the library goes through `get_socket`
  (checked in the installed source). Forty benign lookups run together were all answered with an
  observation in 0.1 to 0.8 s and none was refused for lack of a seat. Of 119 mutants of the code
  109 were killed and the 10 survivors are equivalent or minor. The module passes 5 times at rest
  and 3 times with 8 processes using the CPU on 4 cores (22 to 24 s), and the tests of the WHOIS
  service and of the orchestrator written before this change, which run the real child at `nice`
  10, give 837 passed, 1 skipped, also under that load. Suite 3186 to 3274 passed, 1 skipped, 0
  failed, in 80.09 s (limit 90 s; 60.35 s before: the module takes about 12 s and every WHOIS
  lookup of the tests written before this change starts a child, about 66 ms); 0 ruff
  violations. Nothing was measured on production data. **Declared limit**: (a) The check was made
  with fake servers on the loopback interface and with replies rebuilt from the documented formats
  (a hop of 0.1 to 3 KB, a lookup of at most 6 KB, a longest line of 1.7 KB); no real reply was
  captured, so the caps (8 KB and 64 KB), the CPU limit of the child (4 s) and the deadline (15 s)
  are not calibrated on real traffic. A legitimate reply longer than a cap is read up to the cap and
  the fields after it are lost, and a parser that needs more than the CPU limit on a legitimate text
  gives the fixed error. (b) The suite ran on Python 3.13; the child was also run on 3.12.3, the
  same minor version as the image, but the suite was not, and nothing was run in the Docker harness
  or in the container. The tests that look at the child read `/proc` and are for Linux only. (c) An
  outcome in error, the expiry of the child included, stays in the cache of the service for
  `CACHE_TTL`, like the other errors; only the outcome with no free seat is not saved. (d) Other
  limits of the lookup are tracked separately. (e) The times come from a development machine, not
  from the Docker harness of the project.
- **A value written inside an `on*` attribute of the dashboard (the handlers of its buttons and
  rows) could leave the JavaScript string that held it, because `esc()` does not protect that
  position: the HTML parser decodes the entities of an attribute before the JavaScript engine reads
  the code, so an encoded quote came back as a quote (`SEC-37`; found in the root-cause
  investigation of `SEC-34`, which inventoried the 296 interpolations of the page).** Names of
  domains, clients and users were written into the handlers as `'${esc(value)}'`, a string in single
  quotes. `esc()` turns `'` into `&#39;`, which is right for the markup and wrong for the code:
  after the decoding the engine reads `'` again, so a value that holds a quote and a call closes the
  string and the rest of the value runs as code. The ids were written with no quotes and no `esc()`
  at all. The values that an authenticated user can save reached some of these buttons, so a value
  saved by an authenticated user could run as code when another user clicked a button. **What
  changes.** Only `services/dashboard_app.html`, 54 lines changed (29 added, 25 removed). One
  helper, `jsArg`, next to `esc()`: `const jsArg = v => esc(JSON.stringify(v) || "null")`. Every
  value inside a handler is written as `${jsArg(value)}`, with no quotes around it: 29
  interpolations, 12 that were quoted strings (domain, client and user names) and 17 that carry an
  integer id, an index or a flag. After the decoding the engine reads a JSON literal (a string, a
  number or a boolean), and the content of a JSON string cannot close it, whatever characters it
  holds. The types of the arguments do not change: an id remains a number, a flag a boolean, a name
  a string. A value that is absent arrives as `null` (before: an empty string) and the handler
  remains a valid expression: `JSON.stringify` returns `undefined` for an absent value, and the
  helper writes `null` in its place, or the argument list would be left with a hole. The ids go
  through the helper too, so that the rule is the same for every value of a handler and can be
  checked. The `<option value>` of the list of users and the label of the type in the onboarding
  chips, which were written as they came, pass through `esc()`. No `shared/`, endpoint, trust zone,
  dependency, port, `Dockerfile` or SQLite schema is touched, and a rollback restores the previous code with
  no migration. **Measured.** 227 new tests, only added, no existing test touched
  (`tests/dashboard_render.js` is not modified): the module `tests/test_dashboard_handlers_sec37.py`
  (1,388 lines) and the evaluator `tests/dashboard_handlers.js` (190 lines), both new. On the
  previous page 96 fail and 131 pass: the failures are the hostile text in a field (16), the forged
  id (50), the absent value (5), the `<option>` and the chip label (2), the static guard (3) and the
  helper (20); the passes are the controls, which are the types of the arguments, the exact text of
  the buttons for real values, the checks of the evaluator, the behaviour of the guard on small
  sources, and the hostile text in the views whose handlers carry no text. The tests run the real
  script of the page in node (the `--sinks` mode of `SEC-34`), read the text of every `on*`
  attribute with an HTML parser that decodes the entities as a browser does, and run each one in its
  own isolated `vm` context, whose stubs record the calls, with a probe that exists only in the
  stubs: if the probe is among the calls, the value closed the string and was run. The hostile
  values are inert (they call only the probe) and come in ten kinds: single and double quote,
  parenthesis, backslash, backslash and quote, raw new line, `</script>`, a value that is itself an
  encoded entity, U+2028 and U+2029, and a closing of the attribute that opens another. A guard on
  the source of the page requires that inside an `on*` attribute there is only `${jsArg(…)}`, in a
  quoted value, written whole inside its tag. Independent verification: with parse5 (a conforming
  HTML5 parser) 1,120 targeted cases and 48,000 random ones, none leaves the list of arguments (the
  one difference, an object with a `__proto__` key, runs nothing and never reaches a handler), and
  the same control with the previous technique fails 25,069 times; the security review ran 122,443
  checks through `jsArg`, the attribute, parse5 and a `vm` (entities with and without `;`, NUL, C0
  and C1 controls, U+2028 and U+2029, surrogates, `</script>`, `<!--`, types that are not strings,
  120,000 random strings) with 0 failures against 1,190 for the previous technique, and a second
  decoder written from the specification agrees. End to end, with the real service and the real
  render, the probe ran 14 times over 2,072 handlers on the previous code and none on this change,
  which also gives none over 315 handlers of the Clients, Users and onboarding views. Comparing the
  previous page with this change on 5 seeds of 483 scenarios, normal values give 0 differences in
  function, arguments and types, and the same HTML byte for byte except the value of the `on*`
  attributes, while values with special characters gave 160 to 212 handlers in `SyntaxError` (a
  button that does nothing) on the previous page and none on this change. The inventory of the page
  by syntax tree found 29 of 29 interpolations of handlers through `jsArg`, and no concatenation,
  `setAttribute` or `javascript:`. Of 168 mutants 165 were killed and the 3 survivors are
  equivalent. Without node the behavioural tests skip, as the other rendering tests do, unless
  `DOMAINSENTRY_REQUIRE_NODE=1`; the ones on the source do not need it. Suite 2959 to 3186 passed, 1
  skipped, 0 failed, in 60.35 s (limit 90 s); 0 ruff violations. Nothing was measured on production
  data. **Declared limit**: (a) the handlers remain inline in the page; further hardening of the
  page is tracked separately. (b) The check was made with the real script of the page in node, with
  an HTML parser in Python and one in node, not in a browser. (c) The raw characters U+2028 and
  U+2029 inside a literal need a JavaScript engine of ES2019 or later. (d) The times come from a
  development machine, with Python 3.13 and node 22, not from the Docker harness of the project.
- **Nine values that the dashboard expects to be numbers were written into the HTML with no escape,
  so a snapshot field that held markup instead of a number reached the page of an authenticated
  analyst, or the downloaded HTML report, as markup (`SEC-34`; found in the security review of
  `COL-16`, which reported the reputation score, and extended by the root-cause investigation to an
  inventory of the 296 interpolations of the page).** The nine are the counter of hidden content
  (`hidden_elements.risk_indicators`), the status code and the length of the HTTP check, the total of
  certificates (in the Intel tab and in the downloaded report), the reputation score, the number of
  cases of the report, the open cases of each client and the counts of the summary cards. The text
  fields next to them (URL, server, title, issuer, registrar) went through `esc()`; these nine were
  written as they came because they were expected to be numbers. The snapshots are
  persisted as the services send them, with no check of the type, so a value is a number only as
  long as every service and every hop between services sends one. Six of the nine come from the
  snapshots (the counter, the status, the length, the two totals, the score); the other three are
  counts that the server computes or that the page takes from the length of a list (the cases of the
  report, the open cases of a client, the summary cards), and they are escaped too so that the rule
  is the same for the nine and can be checked. **What changes.** Only `services/dashboard_app.html`,
  9 lines changed (9 added, 9 removed). `esc()`, or `e()` inside the report builder, wraps the whole
  value with its fallback in place: `esc(ch.status_code || "—")`, `esc(ch.content_length || 0)`,
  `esc(rep.risk_score != null ? rep.risk_score : "—")`, and `esc(openCases)` inside the branch that
  tests `openCases != null`. No expression is moved and no helper is added. The rendering of
  the real values (integers, zero, `null`, a missing key) is the same byte for byte: 78 fixtures
  identical and 589 comparisons of values, with differences only for values that carry special
  characters, which come out as text, and for a report whose `case_count` is missing, which prints an
  empty text instead of `undefined` and which the page never builds (it sets `case_count` from
  `cases.length`). No `shared/`, endpoint, trust zone, dependency, port, `Dockerfile` or SQLite
  schema is touched, and a rollback restores the previous code with no migration. **Measured.** 53 new tests,
  only added, no existing test touched (the harness `tests/dashboard_render.js` gets 119 lines and
  loses 1). On the previous code 14 fail (eight sites with one test each, and the six fields of the
  summary that feed the cards) and 39 pass: those are the controls, the exact text of the cell or of
  the heading for real values, zero, `null` and a missing key, and the text fields next to the
  numbers, which stay escaped text. The tests run the real script of the page in node, in a `vm`
  context with a stub of the DOM (`tests/test_dashboard_render_sec34.py`, new, 498 lines), with an
  inert marker, an element with an id and no code (`<b id=x34-field>`), in one field at a time:
  without the escape the parsed HTML holds that element, with it the marker is text. The harness
  gets a `--sinks` mode that calls a function of the page by name, only one that the page itself
  declares (`eval`, `Function` and `constructor` are refused), with `api()` replaced by the payloads
  of the scenario, and records per element id what the script assigns to `innerHTML` and
  `textContent`; that is what lets the Clients view and the summary be driven. The output of the
  default driver is byte-identical on 78 cases, on an empty list and on an invalid input. Without
  node the tests skip, as the other rendering tests do, unless `DOMAINSENTRY_REQUIRE_NODE=1`.
  Independent verification: the inventory of the page by syntax tree counted 296 interpolations; the
  verifier ran its own dynamic taint over the 296 (4,226 executions, 244 reached, the other 52 being
  outside the HTML) and found no site missing from the inventory. End to end on the six values
  that come from the snapshots (forged output of a service, real persistence, real endpoint, real
  render) the previous code produced 5 injected elements in the Intel tab and 1 in the report, and
  this change 0. The security review ran a matrix of the 14 data paths by 12 classes of payload with
  no failure, 669 scenarios of the downloaded report with no unescaped data, and a fuzz of 4,385
  scenarios over 16 rendering functions (243 of the 296 interpolations covered by the engine) in
  which the nine values come out as text in every scenario. Of 45 mutants the verifier killed 38 and
  the 7 survivors are equivalent or change nothing in the output; the 29 mutants of the test author
  were all rejected (sites restored one at a time, wrong fixes such as `x || "—"` that turn a zero
  into the dash, `esc()` taken off the fields next to the numbers). Suite 2906 to 2959 passed, 1
  skipped, 0 failed, in 59.26 s (limit 90 s); 0 ruff violations. Nothing was measured on production
  data. **Declared limit**: (a) the values stay persisted as the services send them: this change
  escapes them where the page draws them and does not validate them where they are saved. (b) Other
  hardening of the page is tracked separately. (c) The check was made with the real script of the
  page in node and a stub of the DOM, not in a browser. (d) The times come from a development
  machine, with Python 3.13 and node 22, not from the Docker harness of the project.
- **When the WHOIS server of a registry did not answer (connection refused, timeout, reset, an empty
  reply) or answered with a limit on requests, `python-whois` did not raise but returned a record
  with every field empty, and the service took it for a valid observation and deduced
  `privacy_protected` from the missing registrant (`COL-17`; found in the root-cause investigation
  of `COL-13`).** The library replaces the socket error of the registry server with a text of its
  own and hands it to the parser of the TLD, which does not raise. In a sweep of the real parsers
  (107 suffixes, 642 combinations of suffix and failure text), 606 combinations were accepted as an
  observation without an exception. For the TLDs whose server the library knows without asking IANA
  (68 in the investigation, among them `de`, `nl`, `ca` and `jp`) every network failure was silent;
  for the others it was silent when IANA answered and the registry did not.
  `services/whois_intel.py` answered `error: null` with every field `None`, so `collection_failed`
  saw a valid section and the empty record replaced the baseline instead of the baseline being
  carried (`COL-13`, `CODE-23`). Effects measured on the previous code, with the real library and
  the real chain and only the network replaced: (1) in the cycle of the outage the case fell from
  `likely_third_party` LOW to `needs_review` MEDIUM (`no_matching_rule`), because
  `collection_failed` judges a module by its `error`, the section had none, and neither the carry of
  `COL-13` nor the guard of `CODE-23` applied; (2) a case closed at LOW was reopened automatically
  (LOW to MEDIUM) and stayed `new` on return; (3) `whois_registrar_changed` HIGH was masked when the
  registrar changed across the outage, because the baseline was by then the empty record and the
  diff needs the registrar of the baseline, and only a `whois_privacy_removed` LOW came out; (4) a
  young homoglyph that goes from resolving to dormant across the outage fell from `suspicious` HIGH
  to `needs_review` MEDIUM for the whole dormant period (up to 30 days), because `COL-14` reuses the
  last snapshot and the empty one looked valid and fresh; (5) on return a false
  `whois_privacy_removed` LOW whenever the registrant was visible again. **Why not the text of the
  error.** The library puts `Socket not responding: ...` in the text it gives the parser, but that
  text does not cover an empty reply or a rate-limit notice, and a registrant can write the same
  string in a field of their own record: their WHOIS would then count as failed and the diffs would
  go blind. The rule looks at the fields returned, not at the text. **What changes.** Only
  `services/whois_intel.py`, 27 lines added and none removed. An outcome with no observed field is a
  collection error: the service answers with `error` set to one fixed text of its own
  (`WHOIS_NO_RECORD_ERROR`, never the text of the library or the notice of the registry, which can
  name addresses and URLs) and with the shape of the answer it gives when the library raises (fields
  `None`, lists empty, `privacy_protected` false). The observed fields are `registrar`, the three
  dates, `status`, the name servers and the name, organization and country of the registrant. They
  do not include the email of the registrant, which the library collects from any address in the
  text, a notice of the registry included, nor the deduced values `dnssec`, `privacy_protected` and
  `age_days`; both `email` and `dnssec` are cleared on the failed answer. The check sits on the
  final result, after the library branch and the `whois` command branch, and raises into the
  existing exception branch, so the log line, the sanitizing and the cache are those of any other
  error and the inferences do not run. The command branch gets the fixed text also when the binary
  cannot start: that error used to read `CLI fallback: [Errno 2] ...` and reached the response. The
  rest is done by the mechanism in place: `collection_failed` carries the last observation with the
  marker of `COL-13`, the guard of `CODE-23` classifies `insufficient_data`, a closed case is not
  reopened by it (`CODE-26`), nothing is raised on return, and `COL-14` finds a readable WHOIS to
  reuse. A record with at least one observed field, even a minimal or redacted one, stays an
  observation. No `shared/`, endpoint, trust zone, dependency, port, `Dockerfile` or SQLite schema
  is touched, and a rollback restores the previous code with no migration. **Measured.** 103 new tests, only
  added (951 lines: 429 in the new `tests/test_whois_intel.py`, 411 in `tests/test_orchestrator.py`
  and 111 in `tests/conftest.py`, no existing line touched): 68 run the real service and the real
  library with only `NICClient.get_socket` replaced, so no connection is opened (an unexpected
  server fails the test; the command branch uses a double of `subprocess.run`), and 35 run the real
  chain from `_run_pipeline` to the case-manager. On the previous code 73 fail (46 in the new
  module, 27 in the chain) and 30 pass: those are the controls, among them a full, a redacted and a
  minimal record, a single observed field for each of the nine, an unreachable IANA, a domain
  unknown to the registry and a normal output of the command. On the chain, sequences ok, registry
  outage for one or two cycles, ok: for refused, timeout, empty reply and rate limit the saved
  section of the cycle of the outage is the last observation with its marker, the classification is
  `insufficient_data`, and no alert comes out in any cycle (the previous code raised
  `whois_privacy_removed` LOW on return). For refused and empty reply, a case closed as a false
  positive stays closed through the outage and after it (it was reopened), a change of registrar
  across the outage raises `whois_registrar_changed` HIGH on return (it was masked), and the young
  homoglyph stays `suspicious` HIGH in the dormant cycle (it fell to `needs_review` MEDIUM). In the
  sweep of the real parsers 606 of 642 combinations were accepted as an observation on the previous
  code and none with this change. The verifier ran an end-to-end bench of 10 scenarios and 15 forms
  of outcome: 10 pass from observation to error, 5 stay observations (a `.it` `AVAILABLE`, a record
  without registrant under GDPR, a `.de`, a `.eu`, a standard `.xyz`), and no readable WHOIS became
  an error. Of 31 mutants of the check, 30 are killed and the survivor is an equivalent; three that
  survived the first tests (a return that skips the cache, `dnssec` left set on the failed answer,
  the text `CLI fallback` kept) are killed by 5 cases added after the first verification. The
  security review found no new route, dependency or secret, an error text that was always the fixed
  one and never echoed a marker, in the response or in the log, over 6 payloads on 2 TLDs, and in
  the isolated tests 0 connections, 0 subprocesses and 0 writes outside `tmp_path`. Suite 2803 to
  2906 passed, 1 skipped, 0 failed, in 59.63 s (limit 90 s); the verifier measured the delta due to
  this change at +3.1 and +3.9 s on three pairs of runs of the previous code and of this one; 0 ruff
  violations. Nothing was measured on production data. **Declared limit**: (a) a domain whose WHOIS
  the library cannot read in a persistent way (a TLD with no parser for its format, an unreadable
  format) is `insufficient_data` MEDIUM, like any module that collects no data (`CODE-23`:
  incomplete data does not count as benign). A case classified `needs_review` keeps its severity;
  for a benign classification with an empty WHOIS, a parked page at LOW for example, the severity of
  the case rises to MEDIUM. (b) The empty snapshots saved before this change are not cleaned. At the
  first readable cycle after the deploy a `whois_privacy_removed` LOW can come out once for a domain
  whose baseline was empty and whose registrant is visible, and a dormant young homoglyph can reuse
  an empty snapshot as long as it is fresh (up to 30 days), because in the dormant cycles nobody
  collects the WHOIS. (c) A partial record from the second hop and a network error that one specific
  parser reads as a field are not covered by the rule of no observed field: tracked separately. (d)
  An outcome in error stays in the cache of the service for `CACHE_TTL` (24 h by default), like the
  other errors. (e) The times come from a development machine without Docker, with Python 3.13, not
  from the Docker harness of the project.
- **A reputation source that failed on its own was saved as zeros and became the baseline, so when
  the source came back the diff raised `vt_malicious_detected` CRITICAL or `otx_pulse_detected` HIGH
  for a value that had been observed before the outage (`COL-16`; found in the root-cause
  investigation of `COL-13`).** With one source of the `reputation` module in error (VirusTotal
  answering 429 or 5xx, a timeout, a reply that is not JSON; OTX the same) and the others answering,
  the module did not count as failed: `collection_failed` declares it failed only when every queried
  source is in error (`CODE-14`), and the carrying rule of `CODE-01` and `COL-13` decides for the
  whole module. The section was saved as it came, with the failed source as a complete dict with
  every number at zero and `error` set, and it overwrote the last good reading of that source. When
  the source came back, `/diff` compared the real value with the stored zero and raised the alert
  for something the baseline had held before the outage. The persisted risk score fell in the cycle
  of the outage as well (50 to 10 with VirusTotal down, because the score leaves out the sources in
  error), and nothing in the snapshot said that the figure was not an observation. The case did not
  change (no case rule reads reputation, it stayed `likely_third_party` LOW), so the false alert
  reached the history of alerts only. **Why `/diff` alone was not enough.** The snapshot of the
  cycle in outage, timestamp aside, is identical whether the source held 3 malicious before the
  outage (the alert on return is false) or 0 (it is true): once that cycle has overwritten the
  baseline, nothing stored tells the two apart, and a prototype that changed only the comparison
  lost the true alerts. The last good reading has to be kept when the snapshot is written. **What
  changes.** (1) `_persist_intel` carries per source (`_carry_reputation_sources`, in
  `services/orchestrator.py`): for `virustotal`, `otx` and `securitytrails`, a source that was not
  observed in the cycle and that the previous section had observed, or was already carrying, keeps
  the previous reading in the saved section; the sources that answered, and the `timestamp` of the
  section, are those of the cycle. The saved section gets `reputation.carried_sources = {source:
  {observed_at, carried_at}}`, one entry per carried source. `observed_at` is the one of the
  previous marker for that source when it was already carried, otherwise the `timestamp` of the
  previous section, and it is `null` (age unknown) when that instant is unreadable or lies after the
  cycle, with the same parse as the DNS parts of `COL-12`. `carried_at` is the instant of the cycle,
  read once and shared with those DNS parts and with the `carried_over` of `COL-13`. The key is
  distinct from `carried_over` and the two coexist: a total outage after a partial one keeps the
  marker of the source. The marker lives in the snapshot only, not in the observation of the cycle
  that events and classification read, so events, classification and the payloads sent to the
  classifier are identical with and without it, and the case does not change classification. A
  `carried_sources` that arrives inside the response of the service (the unauthenticated zone) is
  dropped: only the orchestrator writes it. (2) "Not observed" means `error` present and not `None`,
  decided by presence and not by the truth of the text (`SCO-05`): an exception with no message
  gives `error: ""` and is a failure like the others. The one exception is the 404 of VirusTotal,
  which is an observation (VirusTotal answers that it does not know the domain, so the zeros are
  true). Its text is one constant, `VT_NOT_FOUND_ERROR` in `shared/constants.py`, used by the
  collector and by the readers instead of a literal repeated across files. A source that was not
  queried (`None`: key missing or left out of `sources`) and a source with no earlier observation
  are not touched. (3) When at least one source is carried, the score is recomputed on the saved
  section: `_calc_score` and `_score_to_level` move unchanged from `services/reputation.py` to
  `shared/utils.py` (the collector imports them from there), so the cycle in outage no longer lowers
  the persisted risk. (4) `/diff` does not alert on a source that was not observed on either side
  (`reputation_source_unobserved`, one predicate in `shared/utils.py` used by the orchestrator and
  by the classifier): a zero from a failed source is not a reading, as baseline or as current cycle,
  and the first observation of a source that never had one fills the baseline in silence, the
  principle of `_has_baseline`. (5) A guard on invalid data. The sections come from an
  unauthenticated service (the cycle) and from disk (the previous one), and carrying copies and
  recomputes. With numbers that are text, a source nested beyond the limit of `copy.deepcopy`, or a
  non-finite float added to a huge integer (`NaN` and `-inf` are valid JSON), carrying would raise
  and `_persist_intel` would propagate it: the snapshot of the domain would not be saved and, in the
  variants branch, neither would the classification. One guard, on `TypeError`, `AttributeError`,
  `ArithmeticError` and `RecursionError`, falls back to the section of the cycle as the service sent
  it, without incoming markers, and writes one warning with the class name of the exception and
  nothing of the payload (not the text of the exception, not the keys of the section). A poisoned
  snapshot on disk is replaced at the first cycle instead of being carried at every cycle. `shared/`
  is touched by the constant, the predicate, the two moved functions and the import of the constant
  in `shared/utils.py` (`shared/constants.py` imports nothing, so no cycle), and by nothing else; no
  endpoint, trust zone, dependency, port, `Dockerfile` or SQLite schema changes. The marker is an
  additive key of the snapshot: the previous code ignores it, and the first cycle in which the
  module answers replaces the section, so a rollback needs no migration. **Measured.** Sequences ok,
  one source in error for one or two cycles, ok with the same verdict, run through the real
  collectors, `_persist_intel` and the real `/diff` with only the network replaced: no alert in any
  cycle for the 6 forms of VirusTotal failure of the investigation (429, 429 for two cycles, 500,
  timeout, connection error, a 200 that is not JSON) and the 2 of OTX (429, timeout); on the
  previous code every one of them raised the alert on return. The true alerts are kept: VirusTotal
  from 0 to more than 0 malicious across an outage of one or two cycles (`vt_malicious_detected`
  CRITICAL, once, on return), the same after a 404, and OTX with more pulses from 0 or from some
  (`otx_pulse_detected` HIGH), as without an outage. The persisted risk stays 50 `medium` through
  the cycles of an outage of VirusTotal (it fell to 10 `low`) and of OTX (it fell to 40), and with
  VirusTotal carried and OTX at 5 pulses it is 65 `high`, computed on the saved section. 313 new
  tests, only added (1625 lines, no existing test touched): 224 in `tests/test_orchestrator.py`, 66
  in `tests/test_classifier.py` and 23 in `tests/test_reputation.py`. On the previous production
  code 202 of them fail (176 and 26) and 111 pass: those are the controls, among them the 23 of
  `tests/test_reputation.py`, which fix the shape and the score of the collector output, not covered
  before, guard the move of the score functions, and are green before and after. Suite 2490 to 2803
  passed, 1 skipped, 0 failed, in 51.94 s (limit 90 s); 0 ruff violations. Independent verification
  in four rounds of the verifier and three of the security reviewer found three things, all fixed in
  this change: carrying raised on invalid data (point 5, first with `TypeError`, `AttributeError`
  and `RecursionError`); `OverflowError` escaped that first guard (a non-finite float plus a huge
  integer, 54 in 120,000 hostile cases, so the guard takes `ArithmeticError`); and the fallback was
  silent (it now leaves the one warning). Three mutants that survived the first tests are now
  killed: the incoming marker dropped after the check of the previous section, a fresh `now_iso()`
  in place of the instant of the cycle, and a log that prints the text of the exception or the keys
  of the section. Final rounds: a matrix of 23 end-to-end scenarios with the alerts where they must
  be and nowhere else; a fuzz of 3,000 pairs of sections with 0 violations of the invariants; a
  hostile fuzz of 3 x 60,000 combinations in which nothing escapes the function, with about 43,000
  log lines, all in the fixed format; a security review with 3 x 120,000 fuzz cases, the 55 routes
  unchanged with the same dependencies, no new secret, no import cycle or effect at import, and a
  log that carries class names only (360,000 hostile cases give 3 distinct messages of at most 62
  characters); 42 mutants of the guard, the discard of incoming markers, the instant of the cycle,
  the unreadable timestamp and the log, 40 killed, the two survivors being an equivalent (`except
  Exception`) and a contrived log of one scalar field. **Declared limit**: (a) VirusTotal going from
  3 to 5 malicious across an outage no longer alerts. It did before only through the zero that the
  outage left as baseline, and it is now consistent with 3 to 5 without an outage, which never
  alerted: the rule of VirusTotal is only 0 to more than 0. (b) The first observation of a source
  that never had one fills the baseline in silence, and that includes the snapshots already saved
  with a source in error before this change: a true 0 to more than 0 in that window raises no alert.
  (c) A source that is blind in a persistent way stays carried with no alert of staleness; the
  dashboard does not show which source is carried, and the SIEM event publishes the score of the
  cycle and not the saved one. These are tracked separately. (d) The times come from a development
  machine without Docker, with Python 3.13, not from the Docker harness of the project; the test
  that nests a source beyond the limit of `copy.deepcopy` assumes that `json.loads` holds that
  depth, which is true on Python 3.12 and 3.13.
- **The suite took 83.55 s against the project limit of 90 s, and repeated runs on the same machine
  ranged from 82.5 to 93.5 s, so a run could cross the limit with no test having changed
  (`BUILD-06`).** Most of that time was computing, not testing. The password hash is PBKDF2 at
  600,000 iterations, about 0.2 s per call, and the suite computed it 129 times, 26.5 s in total:
  21.0 s at every login and every user created in `tests/test_case_manager.py`, and 5.3 s for the
  admin that `init_db()` creates in each of the 25 scenarios of `tests/test_col02_chain.py`. The
  local HTTP servers of the tests added waits with no purpose. `serve_forever` checks for the
  shutdown request every 0.5 s by default, so each of 9 tests waited up to half a second when it
  closed its server (about 4.4 s); and the server that stalls halfway through a body slept a fixed
  4 s after the client had given up at 1 s, and the test waited for it (about 3.0 s). **What
  changes.** Only `tests/`: no served code, image (the `Dockerfile` copies `shared/`, `services/`
  and the entry scripts, not `tests/`), dependency or workflow. (1) `tests/conftest.py` sets
  `shared.auth.PBKDF2_ITERATIONS = 1000` in the test process only. It is at module level and not in
  a fixture because the admin of `services.case_manager` is created when
  `tests/test_case_manager.py` is imported, during collection and before any fixture runs: as a
  session fixture 28 tests fail, with the hash created at 600,000 iterations and checked at 1,000.
  It is not an environment variable read by `shared/auth.py`, because that would put in the served
  code a switch that lowers password hashing, and a wrong value in the environment of the container
  would weaken it without a sound. The import is guarded against `ImportError`, so a `pytest` run
  without `shared` on the path runs the tests that do not need it, such as the dashboard rendering,
  as before. (2) The served cost stays 600,000 and is pinned by
  `TestAuthPrimitives::test_served_pbkdf2_cost_is_not_lowered`. In a clean interpreter, a subprocess
  that never loaded the override, with a spy on `hashlib.pbkdf2_hmac` installed before the import,
  it asserts that the constant is at least 600,000, that `hash_password` and `verify_password` each
  pass at least 600,000 iterations to PBKDF2, and that the subprocess imported the same
  `shared/auth.py` as the test process. Without it the override would hide a lowered cost for good.
  (3) The local HTTP server of `tests/test_utils.py` runs `serve_forever(poll_interval=0.01)`, and
  the fixed `sleep` of the stalling server is a wait on a `threading.Event` that the test sets after
  the client has returned. The client sees the same silence for the same 4 s, so its read timeout
  fires at 1 s as before; only the tail after the client has gone changes. **Measured**: the full
  suite goes from 83.55 s to between 47.9 and 49.6 s over eight runs (limit 90 s), and from 2489 to
  2490 passed, 1 skipped (the one new test, which costs 0.03 s); without `node`, from 2379 to 2380
  passed with 111 skipped, in 47.55 s after the change; 0 ruff. Undoing each change on its own, the
  time returns by +26 s (override), +4.4 s (poll interval) and +3.0 s (event). No test depends on
  the PBKDF2 cost: the suite is also green with 1 iteration. No assertion was removed or changed
  (`--collect-only` differs by the new test alone). Independent verification by mutation of
  `shared/auth.py`: the constant lowered, a literal in place of the constant in either
  `hash_password` or `verify_password`, a default `iterations=1000`, and a cost read from `environ`
  with the variable set were all red; refactors with the same behavior stayed green. **Declared
  limit**: (a) when moving on one machine between a checkout with this change and one without,
  delete `/tmp/cm_svc.db` and `/tmp/test_feed_*` first. A user database left by the other version
  holds hashes computed at a different cost, and its logins fail (37 tests fail with HTTP 401). The
  underlying cause, fixed paths reused between runs, is tracked separately. (b) The test pins the
  iterations that `shared/auth.py` passes to PBKDF2. It does not check the algorithm, the key length
  or the call sites in the services, a computation that bypasses `hashlib.pbkdf2_hmac` on purpose is
  not seen by it, and a cost read from the environment is seen only if the variable is set in the
  environment of the test process. Those improvements are tracked separately. (c) The times come
  from a development machine without Docker and with `node` on the path, not from the Docker harness
  of the project or a hosted runner.
- **A CI runner without `node` stayed green without running the 110 rendering tests of the
  dashboard, because those tests skip themselves when `node` is missing (`BUILD-07`; found in the
  independent verification of `CODE-51`).** The tests that `CODE-51` added run the real script of
  the page in `node` and, like the TLS tests with `openssl`, skip when the binary is not found. In
  the Docker harness of the project that is what happens (111 skipped), which is fine on a
  development machine; in CI it meant that a runner image without `node` would report a green suite
  that never exercised the rendering, with the protection of `CODE-51` gone and nothing in the log
  to say so. The entry of `CODE-51` left requiring `node` in CI as tracked separately; this is that
  change. **What changes.** With `DOMAINSENTRY_REQUIRE_NODE=1` in the environment, a missing `node`
  turns the skip into an error on all 110 rendering tests (`ERROR at setup`, with a message that
  names `node` and the variable), so the suite exits non-zero. The `test` job of
  `.github/workflows/ci.yml` sets the variable on the pytest step and prints `node --version` just
  before it, to tell from the log which `node` the run had. Only the value `1` activates it: any
  other value (`true`, `yes`, empty) leaves the skip, so a typo in the workflow would switch the
  guard off without a sound, and the comment in the workflow notes it. Without the variable (local
  development, the Docker harness) nothing changes: the rendering tests skip as before. No product
  code, image, dependency or action changes, and no job other than `test`. **Measured**: 5 new
  tests in `tests/test_dashboard_render.py` (`TestMissingNodeDecision`), which call the real
  fixture with `shutil.which` and the environment replaced, so they start no `node` and cost under
  0.2 s; on the previous fixture 2 fail (a missing `node` with the variable set skips instead of
  failing) and 3 pass as non-regression (without the variable it still skips; with `node` present
  the rendering runs with or without the variable). Of the existing tests only the fixture
  `rendered` and the module docstring changed (compared by AST). Without `node` and with the
  variable the previous code gave 110 skipped and exit 0; now 2379 passed, 1 skipped, 110 errors
  and exit 1. With `node`: suite 2484 to 2489 passed, 1 skipped, with and without the variable;
  without `node` and without the variable: 2379 passed, 111 skipped, as before. In 83.7 to 88.7 s
  over the four configurations (limit 90 s); 0 ruff. Independent verification by mutation: 11 of 11
  mutants of the fixture and 7 of 7 of the workflow killed. **Declared limit**: the workflow has
  never run on a real push or pull request, so this was verified here (the four configurations
  above, the YAML parsed), not by the hosted runner. If that runner had no `node`, the
  `node --version` step would fail the job at once, which is the intent: red instead of green
  without the rendering.
- **The tests of the dashboard for `COL-12` and `COL-13` read the text of the source, so a change
  that broke the rendering for every domain, or that inverted a condition, passed the whole suite;
  and an empty observation date printed "ultima osservazione: )" (`CODE-51`; found in the
  independent verifications of `COL-12` and `COL-13`).** The checks of those two changes are static:
  they look for strings and expressions in the source of the page without comments. They do not see
  a guard that was taken out. Removing the `carried[t]` filter of the Intel tab, or the guard of the
  note in the client report, raises `TypeError` on every snapshot, so the report and the Intel tab
  would fail for every domain of every client, and the suite stayed green; a ternary with its
  branches swapped, or an `.error` read from the wrong object, passed too (27 mutants of the page
  that the static tests let through). **What changes.** A test harness, `tests/dashboard_render.js`,
  loads the real script of `services/dashboard_app.html` in a `vm` context of `node` with a minimal
  stub of the DOM and calls the real rendering functions (`buildHtmlReport` for the client report,
  `renderIntelTab` for the Intel tab, the change history included) on test snapshots. It reads only
  the source of the page and its standard input, opens no connection and writes no file, and a
  JavaScript exception is never swallowed: it fails the test that meets it. 110 tests in
  `tests/test_dashboard_render.py` assert on what the rendering shows (the text of each row, the
  presence or absence of a note, the escaping), with one `node` process per test module; 22 tests in
  `tests/test_orchestrator.py` fix the edge cases of the observation instant of a carried DNS part
  (`_dns_observed_at`): an observation equal to the instant of the cycle is kept, and an instant
  without a time zone is compared as UTC with one that has it, with the local zone of those tests
  fixed at +9 hours because on a host in UTC "no zone means UTC" and "no zone means local time" give
  the same result; 4 sentinel tests in `tests/test_dashboard.py` check the comment stripper that the
  static tests rely on (an approximate lexer, which a regular expression literal with a quote can
  fool): no comment survives in the source it returns, and the escaping regular expression survives
  intact. **The rendering fix.** An `observed_at` that is an empty string passed the
  `typeof … === "string"` guard and printed "ultima osservazione: )" in the four places that show
  it (the A and MX notes and the certificates row of the client report, the module notes and the
  DNS row of the Intel tab); it now reads "data ignota", like any value that is not a date. It is
  reachable only by writing into the data directory by hand: the orchestrator writes an ISO instant
  or `null`. A string made only of spaces stays out of this fix and is tracked separately; it is not
  reachable from the pipeline either. Presentation only: no data format, endpoint or schema
  changes, and rolling back needs no migration. **Node.** It is not a dependency of the image nor
  of `requirements.txt`: the tests look for it with `shutil.which` and skip if it is missing, like
  the TLS tests do with `openssl`. The standard CI runner has it. In the Docker harness of the
  project it is not present, so the rendering tests are skipped there (111 skipped, 2374 passed);
  a runner without `node` is therefore green without this protection, and requiring it in CI is
  tracked separately, as is replacing the static tests that turn red on equivalent rewrites of the
  page. This is the test that the entry of `COL-13` declared as tracked separately in point (f).
  **Declared**: the docstrings of three existing test classes of `tests/test_dashboard.py` and the
  comment above a fourth said that the suite had no JavaScript runtime and that a test of the real
  rendering was tracked separately; they now say that those classes are static checks and that the
  rendering is exercised in `tests/test_dashboard_render.py`. Only comments and docstrings changed
  (18 lines removed, 17 added): the rest of the file is identical to the previous one and no
  assertion was touched. **Measured**: 136 new tests (110 + 22 + 4), only added. On the previous
  `dashboard_app.html` 4 fail, the ones for the empty date; the other 132 pass because they pin
  behaviour that was already right and kill the mutants. The rendering of 113 test snapshots by the
  previous page and by the fixed one is identical except for the empty-date case. Independent
  verification by mutation: 305 mutants of the page and 44 plus 4 of the orchestrator; every mutant
  named in the investigation is killed and the survivors are equivalent or only change the
  formatting; after the last refinement of the tests a new run of 204 mutants lost none; no false
  red by test order, time zone, language, Python 3.12/3.13 or node 20/21/22. The 136 new tests cost
  under 1 s (the rendering ones about 0.3 s). Suite 2348 to 2484 in 85.7 s (limit 90 s, which some
  runs exceed because of the variance of the machine): 2484 passed, 1 skipped, 0 failed; 0 ruff
  violations.
- **A dormant homoglyph reused a WHOIS that could be months old as if it were fresh, which froze
  the age of the domain and switched off the re-registration rule (`COL-14`; found in the
  root-cause investigation of `COL-12`).** For a homoglyph that resolves to nothing (no A, no MX)
  the orchestrator does not query the WHOIS again: it reuses the one persisted in the snapshot as
  long as it is an observation of the last 30 days (`SCO-05`, so that the severity of the case
  does not flip between cycles). That freshness was measured on `updated_at`, the instant the
  snapshot was last saved. `_persist_intel` rewrites it at every cycle, and when the WHOIS fails
  it keeps the previous section (`CODE-01`), so `updated_at` says when the domain was last visited
  and not how old the datum is. A WHOIS observed 200 days ago was "fresh" again after a single
  cycle with the WHOIS down, and stayed so for as long as the domain was persisted: `is_aged`
  stayed frozen on that old observation and `recently_reregistered`, which exists to catch an
  expired domain that an attacker registers again, could not fire. **The fix.** The freshness is
  decided on the instant the WHOIS was observed, by the shape of the section. With the
  `carried_over` marker of `COL-13` (an object with `carried_at`) only `observed_at` decides, and
  the `timestamp` next to it does not replace it. Without the marker and with a `timestamp` (also
  the snapshots carried before `COL-13`, which keep the original one) the `timestamp` of the
  collector decides, and the recent snapshot is required too: a recent `timestamp` inside a
  snapshot saved beyond the threshold is incoherent and is not enough by itself. With neither,
  `updated_at` decides, as before. An instant in the future, unreadable, not a string or `null`
  is not fresh; one without a time zone is read as UTC; the comparison is between instants, not
  between strings. The in-process cache is unchanged. **Declared**: (a) when the operator did not
  request the WHOIS in the cycle, the WHOIS that is only carried over stops being reused 30 days
  after the last real observation; before, it never expired as long as the domain was persisted
  again. (b) **Operational note**: the dormant homoglyphs that reuse an old WHOIS before this change go back to
  the classification without WHOIS (`needs_review`, MEDIUM). A case that an analyst closed at LOW
  is reopened at the first cycle after the release, and a young homoglyph can go from HIGH to
  MEDIUM. Measure it before the release with a read-only script over the snapshots that lists, for
  each dormant homoglyph, whether its WHOIS is reused before this change and whether it would be
  reused after it. (c) This change reads the marker of `COL-13` and goes out after it. The other
  findings of the review are tracked separately. **Measured** (independent verification): the
  invariant "the WHOIS is reused if and only if the last one that answered is within 30 days", on
  120 random sequences of cycles with the real persistence (14,387 checks), is violated 744 times
  by the previous code and 0 times by the fix, also when the carrying writes no marker (snapshots
  as they were before `COL-13`); against an independent oracle of the contract on 5,915
  combinations of sections, markers and instants (time zones, formats, epochs, NaN, 100 KB
  strings, malformed markers) there are 0 disagreements and 0 exceptions; on real chains of 130
  daily cycles (real classifier, store and `_persist_intel`, simulated clock, only the network
  stubbed) the severity of the case flips less often: with a domain that alternates between
  resolving and dormant while the WHOIS stays down, 129 flips before and 29 after, none after
  day 30. 30 new tests in `tests/test_orchestrator.py`, only added, no existing test changed; on
  the previous production code 18 fail and the 12 that pass are controls (the fresh side of every
  boundary, the section with neither `timestamp` nor marker, the lookup that must not raise, the
  in-process cache alone). Suite 2318 to 2348 in 76.0 s (limit 90 s; the new tests alone cost
  about 0.7 s): 2348 passed, 1 skipped, 0 failed; 0 ruff violations.
- **A module that did not answer (certificates, WHOIS, HTTP, reputation) showed its previous answer
  as current for as long as it stayed silent: the report said "CT: ok", "Website: active", "WHOIS
  ok" on data that could be days old, and nothing told how old (`COL-13`; found in the root-cause
  investigation of `COL-12`, whose marker it extends to whole modules).** When one of these four
  modules fails as a whole (the service answers with an HTTP error, `error` is set, every HTTP check
  has no status, every reputation source is in error), `_persist_intel` keeps the previous section
  instead of overwriting a healthy baseline (`CODE-01`). That is right for the alerts, but the
  snapshot kept the old section with no field saying so and a fresh `updated_at`: the client report,
  the Intel tab and the Raw view showed it as today's observation for every cycle of the outage.
  Measured on the real chain (the five real collectors, orchestrator, store, `/diff` and
  `/classify/variant` of the classifier, case manager on SQLite, only the network stubbed, simulated
  clock of 24 h per cycle, rendering run with `node`), 5 cycles of outage: certificates (crt.sh
  answering 502) read "Certificates <old count> (CT: ok)"; WHOIS (the lookup raising) kept the old
  registrar and read "WHOIS ok"; HTTP (4 URLs without an answer) read "Website: active" and "HTTP
  ok"; reputation (3 sources answering 500) kept the old score and read "reputation ok". There were
  0 alerts during the outage, and on the way back, with changed data, the ordinary alerts
  (`new_certificate`, `whois_registrar_changed` HIGH, `vt_malicious_detected` CRITICAL) came late by
  the whole length of the outage. The case channel compensated for three of the four modules (for
  certificates, WHOIS and reputation the case already says `insufficient_data`, the guard of
  `CODE-23`); for HTTP no channel compensated: the guard excludes it by construction and the
  classification stayed `likely_third_party` LOW. **The marker.** The `cert`, `whois`, `http` and
  `reputation` sections of the snapshot get a direct field `carried_over = {observed_at,
  carried_at}`: the instant of the last real observation of the module and the instant of the cycle
  that carried it. It is a direct field and not a map by part like the one of the DNS (`COL-12`), on
  purpose: these modules have no parts. `observed_at` is the `timestamp` of the section itself,
  which the four collectors write and which carrying does not renew, so the age is exact from the
  first cycle after the release; it is never inherited from the old marker. In a series of K cycles
  of outage `observed_at` stays the same while `carried_at` follows the cycle; as soon as the module
  answers again the section is the fresh one, with no marker, and a new outage restarts from the new
  observation. `observed_at` is `null` (age unknown, never fresher than the truth) when the
  `timestamp` is missing, unreadable or lies after the cycle that carries it (the comparison is
  between instants and an instant without a time zone is read as UTC); instants are re-serialised
  from the parse, so `Z`, `+02:00` and the basic ISO format give the same saved value. A previous
  section that is missing, `None`, not a dict or already a failure is left as it is, with no marker:
  there is no datum to declare carried, and the dashboard reads a failure as "errore". A
  `carried_over` that arrives inside the response of a collector (the unauthenticated zone) is
  dropped: only the orchestrator writes it. The instant of the cycle is read once per persistence
  and shared with the DNS parts. The marker lives only in the snapshot, not in `intel[name]` that
  events and classification read, so events, classification and cases are byte-identical with and
  without it, and the previous snapshot is never touched. It weighs 0 bytes when the modules answer
  and about 100 bytes per carried module (about 410 in the worst case, under 2% of an average real
  snapshot). `/diff` ignores it: the same alerts, severity and count with and without it for the
  four modules, also when it is malformed. **Dashboard.** In the client report the Certificates row
  reads "(CT: riportato, ultima osservazione: <day>)", or "data ignota" when the instant is unknown,
  and "Module status" reads "WHOIS riportato", "HTTP riportato" and "reputation riportato" instead
  of "ok". The Intel tab opens each of the four blocks (HTTP fingerprint, Certificates, WHOIS,
  Reputation) with a muted line "riportata dal ciclo precedente (ultima osservazione: AAAA-MM-GG
  HH:MM)". When a section has both `error` and a marker, "errore" wins in the report and the tab
  shows no note: a failure is never hidden behind "riportato". A valid marker is an object with
  `carried_at`; the four modules are chosen by name from a fixed list, so a forged `carried_over` in
  `dns` changes nothing ("DNS ok" stays), and neither does a string, an array or an object without
  `carried_at`. What comes from the disk (`observed_at`) is printed only when it is a string, goes
  through `e()` or `esc()`, and reads "data ignota" otherwise. The DNS rendering of `COL-12` does
  not change, except for that guard. **No alert.** This change makes the presentation honest but
  raises no alert for the outage itself: the sources fail often enough (crt.sh above all) for an
  alert on "not observed for too long" to be noisy, such an alert would also fire on modules the
  operator turned off, and for certificates, WHOIS and reputation the case already says
  `insufficient_data`. It is tracked separately, and so is the lack of any signal for HTTP.
  **Declared**: (a) a module the operator did not request for the cycle (WHOIS or reputation turned
  off) that has a previous datum is carried and marked like the others: the report reads "WHOIS
  riportato" with the date instead of "ok", which is the truth; the previous datum stays in the
  snapshot as before. (b) Partial failures within a module are not covered by this change; tracked
  separately. (c) Snapshots that are already in a failure when this is released read "riportato" at
  the first cycle, with the true age, because the `timestamp` is the original one. (d) `/intel` and `/diff` (in `new_baseline` too), the downloadable JSON and the Raw
  view carry the additive field; the previous code does not read it, so a rollback needs no
  migration. (e) In the dashboard an `observed_at` that is not a string now reads "data ignota" in
  the DNS rows of `COL-12` as well. (f) The tests of the dashboard are static checks on the source
  without comments, like those of `COL-12`: they do not see every inversion of a condition, and a
  test that runs the real rendering with `node` in the suite is tracked separately. **Operational
  note**: this change calls `_dns_observed_at` of `COL-12` and goes out after it. The other findings
  of the review are tracked separately. **Review found and fixed in the same change**: the first
  tests of the dashboard accepted the name of the module as optional, so 17 non-equivalent mutants
  of the page survived the suite, among them the ones that bring the defect back
  (`modStatus(i.cert)` without the name reads "CT: ok" again, a note read from the wrong section,
  "riportato" decided before "errore"): the tests now require the name, the pair section/name, the
  precedence of "errore" and the polarity of the note, and all 17 are killed; `String(observed_at)`
  raises on an object with an own non-callable `toString`, which broke the report and the Intel tab
  of a whole client (reachable only by writing straight into the data directory): every place that
  prints `observed_at`, the DNS rows of `COL-12` included, now has a `typeof … === "string"` guard;
  the Intel tab showed the "riportata" note over a section that also declares `error`; and the
  docstring of the carrying function claimed more than the dashboard reads for sections that had
  already failed (HTTP and reputation failures have no top-level `error`). **Measured**: 176 new
  tests (118 in `tests/test_orchestrator.py`, 35 in `tests/test_dashboard.py` and 23 in
  `tests/test_classifier.py`), only added to the existing files. On the previous production code of
  the two files that change, 118 of the 176 fail; the 58 that pass are the controls (the `/diff`
  that is already additive, no marker when the module answers or there is no previous section, a
  malformed previous section that must not raise, the existing DNS rendering). **4 existing tests
  were changed, none weakened**: the four `CODE-01` tests that compared the section saved after a
  module failure with the previous one (`assert saved == prev`: two with a failed certificates
  module, one with reputation, one with HTTP) now compare everything except the new `carried_over`
  key, because that section is by design the previous one plus the marker; they pass on the previous
  code and on the new one. Suite 2142 to 2318 in 77.0 s (limit 90 s; the new tests alone cost about
  1.4 s): 2318 passed, 1 skipped, 0 failed; 0 ruff violations. Independent verification: the real
  chain with 21 scenarios and 144 cycles, events, classification, case, alerts and history identical
  to the previous code except for the marker; differential fuzzing of `_persist_intel` against the
  previous code, 50,000 cases by the verifier and two runs of 20,000 by the security review, 0 new
  exceptions; the 12,000 comparisons of `/diff` of the investigation, 0 different alerts with and
  without the marker; `_cached_homoglyph_whois` and 3,000 `/classify/variant` requests identical;
  the real rendering functions run with `node` on 88 to 90 hostile snapshots, 0 exceptions on the
  final code against 4 to 5 on the previous one (all in the DNS rows of `COL-12`), 0 unescaped
  values, and 24 of 24 renderings without module markers byte-identical to the previous code;
  mutation testing: 46 of 67 mutants killed in the first round, the survivors being 2 cases of the
  orchestrator that the contract leaves open and 17 non-equivalent mutants of the page, the 17 all
  killed after the correction, with 22 of 22 new mutants of the correction killed.
- **A DNS value carried over from the previous cycle showed as current for as long as the DNS
  stayed silent: the report said "A: yes, MX: no, DNS ok" on a zone that had changed, and nothing
  told how old the data was (`COL-12`; found in the security review of `COL-02`, which it
  completes).** With `RES-01` and `COL-02`, a record type (or an SPF, DMARC, BIMI or CAA section)
  that the DNS did not answer takes the value and the status of the previous snapshot, and when the
  whole module fails (`CODE-01`) the whole previous section is kept. That is right for the alerts,
  but the snapshot kept the old value with the copied status (`ok`) and a fresh `updated_at`: no
  field said "carried over", so the client report, the Intel tab and the Raw view showed it as
  today's observation for every cycle of the outage, and an outage hid a real change of that type
  until the DNS answered again. Measured on the real chain (`dns_intel`, orchestrator, store,
  classifier, case manager) in a scratch directory, with a simulated clock of 24 h per cycle,
  for partial failures (SERVFAIL on A, MX, NS, DMARC or CAA), total failures and email-only
  failures, with 1, 3 and 10 cycles of outage: the old value was shown as current for K cycles out
  of K, there were 0 alerts during the outage and the alerts came only on the way back; in the last
  cycle of the outage the report said "A: yes, MX: no, DNS ok" for a zone that already had a new A
  and an MX. One case repeated with the real `dig` 9.18.39 against a stub on loopback, in an
  isolated network namespace, was identical on 6 cycles out of 6. Events and cases were already
  honest for A, MX and NS (`dns_a_status` and `dns_mx_status` say `unknown`, the guard of
  `CODE-23` gives `insufficient_data`) and so contradicted the snapshot; for AAAA, CNAME, SOA, TXT,
  SPF, DMARC, BIMI and CAA no channel compensated. **The marker.** The `dns` section of the
  snapshot gets `carried_over`, a map from part to `{observed_at, carried_at}`: the instant of the
  last real observation of that part and the instant of the cycle that carried it. The parts are
  the 11 that can be carried (A, AAAA, MX, NS, TXT, SOA, CNAME, SPF, DMARC, BIMI, CAA); DKIM and
  the subdomains are not carried and have no marker. It measures **time, not cycles**: the cadence
  of the cycles is not known (there is no internal scheduler, `/trigger` comes from a SOAR, a
  monitoring system or the dashboard) and a domain that is both a target and a dnstwist variant is
  persisted twice in the same run, so a counter of cycles would count 2. `observed_at` is
  inherited for as long as the part stays carried, and the part leaves the marker as soon as `/dns`
  answers for it; with the whole module failed, every part that had a known value in the previous
  section is marked, and the previous marker is rebuilt, never copied. An `observed_at` that lies
  after the cycle that carries it (clock of `/dns` ahead) is saved as unknown (`null`), an
  unreadable or missing one too: an age is never made fresher than the truth, and a negative age
  would silence the alert for ever. Instants are re-serialised from the parse, part names come from
  the fixed list of 11 and never from the keys of the snapshot, and a `carried_over` that arrives
  inside the `/dns` response (the unauthenticated zone) is dropped: only the orchestrator writes
  it. The marker lives only in the snapshot, not in `intel["dns"]` that events and classification
  read, so events, classification and cases are byte-identical with and without it. It weighs 0
  bytes when the DNS answers in full and about 850 bytes in the worst case, 3% of an average real
  snapshot. The status of a carried part stays the copied one: setting it `unknown` would make
  every one-cycle flap on an unchanged zone alert on the way back, because the diff compares an
  `unknown` baseline as empty (`SEC-31`). **The alert.** `/diff` emits `dns_stale_core` (MEDIUM,
  for A, MX and NS) and `dns_stale_other` (LOW, for the other 8 parts) when the age of a carried
  part, `carried_at - observed_at`, crosses 72 h between the baseline (below) and the current
  snapshot (at or above): once per series, at most one alert per group, which lists the parts that
  crossed, computed on the instants of the marker alone, with no clock in the classifier; an
  unknown `observed_at` counts as infinitely old, so the alert comes at the start of the series.
  72 h is 3 daily cycles, and a one-cycle flap on an unchanged zone gives 0 alerts and an identical
  snapshot. The alert goes only to the alert history of the Intel tab, not to events, webhooks or
  cases: for A, MX and NS those already say `unknown` and `insufficient_data`. Two new entries in
  `SEVERITY_MAP` (`shared/constants.py`, the only change outside the three services): without them
  `_alert` gives MEDIUM but `max_severity` counts the type as LOW. Not HIGH because it is not a
  change that was seen but an answer that did not come; a real change shows up on the way back as
  the ordinary HIGH alert, as it already did. **Dashboard.** In the client report, the A and MX rows
  of a carried part read "yes (riportato, ultima osservazione: <day>)", or "data ignota" when the
  instant is unknown, and "Module status" reads "DNS parti riportate" instead of "DNS ok"; the
  Intel tab has a row with the carried parts and the date of their last observation. The alert
  history rows now show the `message` of the alert: they showed `String(detail)` of an object, "—
  [object Object]" on every row, and did so for the old ones too, since they all have a `message`;
  the count of changes in the head of each entry now goes through the same escaping as every other
  field. **Declared**: (a) with a cadence longer than 72 h even a single cycle without an answer
  alerts, because the unit is time. (b) The one-off alert is lost if `/diff` fails in the very
  cycle in which the age crosses the threshold, like every other alert: the diff keeps no state.
  (c) With `/dns` on a different host from the orchestrator and a clock ahead of it by more than
  the interval between two persistences, the observation can lie after the cycle that carries it:
  it is saved as unknown and the first carried cycle alerts at once, with "data ignota", until the
  part is observed again; on one host or with `unified` it cannot happen. (d) For AAAA, CNAME, SOA,
  TXT, SPF, DMARC, BIMI and CAA the history of the Intel tab is the only signal, and nobody is
  notified of it. (e) The marker also appears in `new_baseline` of `/diff`, in the downloadable
  JSON and in the Raw view. **Operational note for whoever deploys it**: release this change together with `RES-01` and `COL-02`, never alone; a
  `COL-02` build without it writes carried values with no marker, and the first cycle of this
  change would date them from the `dns.timestamp` of the previous snapshot, under-estimating their
  age and delaying the alert. At the first cycle after the release, a domain that is already in a
  total DNS failure with an old snapshot produces at most one pair of alerts (`dns_stale_core` and
  `dns_stale_other`) in the history, and no case and no event. The other findings of the review
  are tracked separately. **Review found and fixed in the same change**: the branch of `SEC-31` (total failure with no previous
  section) saved a marker arriving from `/dns` as it was; an `observed_at` after the cycle gave a
  negative age and the alert never came; the report counted the keys of the marker instead of the
  fixed list of parts; and `alert_count` was printed without escaping. **Measured**: 290 new tests
  (246 written before the fix and 44 after the review), only added to the existing files: 140 in
  `tests/test_orchestrator.py`, 131 in `tests/test_classifier.py` and 19 in `tests/test_dashboard.py`.
  On the previous production code of the four files that change, 242 of the 290 fail; the 48 that
  pass are the controls (events and classification identical with and without the marker, no
  marker when the DNS answers, a baseline without `dns`, existing alerts unchanged). **11 existing
  tests were changed, none weakened**: 7 compared the saved section after a total failure with the
  previous one (`assert saved == prev`, 3 in `TestCOL02PersistModuleFailureKeepsThePreviousSection`
  and 1 test with 4 parameters in `tests/test_col02_chain.py`) and now compare everything except
  the new `carried_over` key, because that section is by design the previous one plus the marker;
  4 depended on the date of execution (the `c02_cycle` fixture read the real clock against
  timestamps fixed on 2026-10-20, so once the age exists they would pass 72 h and raise an alert
  those tests do not expect), and the fixture now fixes the clock. Independent verification: 68 of
  76 mutants of the fix killed, 3 of the 8 survivors equivalent and 5 gaps in the tests tracked
  separately; the age computation against an independent oracle on 468 cases with Python 3.11, 3.12
  and 3.13, 0 differences; 11 scenarios of the real chain with events, classification, case and
  snapshot identical to the previous code except for the marker; 120,000 fuzzed inputs on the new
  functions, plus 8,000 hostile `/diff` payloads against the previous code (alerts other than
  `dns_stale_*` identical) and 14,000 hostile snapshots through `_persist_intel`, 0 new
  exceptions; the real rendering functions run with `node` on 21 hostile snapshots and 38 real
  alert messages, 0 exceptions, 0 unescaped values, and the report never says "DNS ok" with a
  carried part. Suite 1852 to 2142 in 81.8 s (77 s before, limit 90 s; the new tests alone run in
  3.1 s): 2142 passed, 1 skipped, 0 failed; 0 ruff violations.
- **A DNS that did not answer was "absent" for every consumer of `/dns`: one failed record type
  overwrote a healthy baseline, raised an alert on the way out and another on the way back,
  switched the rules of absence on and reopened closed cases (`COL-02`, consumers; second of the
  two changes with `RES-01`, with `SEC-31` merged).** Since `RES-01`, `/dns` says for each of the
  7 base types, and for SPF, DMARC, BIMI and CAA, whether the answer was `ok`, `nodata`,
  `nxdomain` or `unknown` (the DNS did not answer: SERVFAIL, REFUSED, a transport failure, a
  packet that cannot be parsed), and sets `error` when all 7 are `unknown`. Nobody read it yet:
  every consumer still took an empty list for "the domain has no such record". Measured on the
  real chain (`dns_intel`, orchestrator, store, classifier, case manager) in a scratch directory,
  with the real `dig` 9.18 in an isolated network namespace: one cycle of total DNS failure on a
  domain with a full baseline gave 15 false alerts, 6 on the way out and 9 on the way back, which
  `RES-01` alone brings to 0; the failure of the A alone gave 1 HIGH alert on the way out and 1 on
  the way back, and the channel of the cases, which no alert history shows, changed verdict with
  the failure: a case closed as `closed_fp` on a domain with A and MX was reclassified
  `suspicious` / `high` / `mx_only_no_web` by a SERVFAIL on the A alone and reopened MEDIUM to
  HIGH, a parking case closed as `closed_benign` was reopened as `needs_review` by a SERVFAIL on
  the NS, and an MX at a privacy-mail provider lost `privacy_mx_provider` (HIGH) for one cycle by
  a SERVFAIL on the MX. **The fix** is in the three consumers; `case_manager`, the SQLite schema,
  the compose file and the trust zones do not change. **Orchestrator.** `_persist_intel` applies
  per part the rule that `CODE-01` already applies per module: a record type, or an SPF, DMARC,
  BIMI or CAA section, that is `unknown` in this cycle is not an observation, so it takes the
  record and the status of the previous snapshot instead of overwriting them with an empty list. A
  previous snapshot without status, such as every one written before `RES-01`, is copied with the
  `unknown` marker removed, that is "known"; with no usable previous one the part stays `[]` with
  status `unknown`. DKIM and the subdomains are not carried, because no alert and no rule reads
  them. It works on a deep copy: `intel["dns"]` is what classification and events read afterwards,
  and stays the observation of this cycle. When the whole module failed (section `None`, or
  `error` set) the previous section is kept, as before; if there is no usable previous one and the
  failed section declares its types `unknown`, it is now saved as the baseline of the domain, for
  `dns` only (the diff reads its `unknown` as empty; for the other modules a saved `[]` or `0`
  would reset the reference): saved as `None`, as before, it left the next cycle with nothing to
  compare. `collection_status` has a `dns` key, true only when the module failed, in the two
  places that build it; a partial `unknown` does not make the module failed, the classifier reads
  it from the payload, so the result does not depend on what the caller declares. The path of the
  dormant homoglyph, which collects nothing, does not declare it. In the events, `dns_a` and
  `dns_mx` stay booleans ("record seen in this cycle": the contract towards SIEM and SOAR does not
  change) and `dns_a_status` and `dns_mx_status` are added: one of the four states, `unknown` when
  the section is `None`, `null` when `/dns` declared nothing or a value that is not one of the
  four, which is never copied into the event; the events of the dnstwist variants that are not
  collected keep the fields of the tool. **Classifier.** `/diff` skips a type whose status is
  `unknown` in the **current** snapshot, and SPF, DMARC, BIMI and CAA whose `status` is. An
  `unknown` that is only in the baseline is compared as empty, because after the carrying it means
  "never known": the first known and non-empty value alerts like an ordinary change (same type,
  same severity, from `[]` to the value), once, and a known but empty one (`nodata`, `nxdomain`)
  does not. That is `SEC-31`, found in the review of the first version of this change, which
  skipped `unknown` on both sides: an empty zone that failed for two cycles and then answered A,
  MX and NS raised no alert, where before `RES-01` it raised 3 (A and MX HIGH, NS MEDIUM), and
  which type stays `unknown` is chosen by whoever runs the zone. A known baseline stays the
  reference through any number of failed cycles: X, failure, Y is one alert X to Y. The rules no
  longer read an undetermined type as absent: `mx_only_no_web` and `mx_only_aged_domain` need a
  determined A, and a not-aged homoglyph with A or MX undetermined and no record seen gets a rule
  of its own, `homoglyph_not_aged_dns_unknown`, still `suspicious` / `high` (the HIGH comes from
  the name and the age, which were observed, and a SERVFAIL must not be able to lower it) with a
  rationale that does not say the domain is dormant. The rules that fire on data that was seen
  (parking NS and IP, marketplace, MX of parking, privacy and forwarding, `homoglyph_resolving`)
  are the same. The collection guard of `CODE-23` counts `dns` among the failed sections when A,
  MX or NS is `unknown` in the payload, or when `collection_status["dns"]` is true:
  `insufficient_data` unless the verdict is `suspicious`; an `unknown` TXT, SOA, AAAA or CNAME
  alone does not turn it on, because no rule reads them. **Dashboard.** The client report says
  "unknown" for A and MX when the section is `null` or the status of the type is `unknown`, not
  "no"; the Intel tab says "DNS non raccolto" for a `null` section and adds a row with the
  undetermined types. Only constant strings are rendered, never the raw status. **Declared**: (a)
  with A, MX or NS undetermined the verdict is `insufficient_data` (MEDIUM) unless it is
  `suspicious`: domains that were LOW (parking, for sale, probable third party, probable
  legitimate) become MEDIUM for that cycle, and a DNS module that does not answer at all leads to
  the same verdict instead of a verdict on an empty DNS. (b) An accepted limit on severity when
  only some base records are undetermined is tracked separately. (c) A closed case stays closed for the
  whole duration of a DNS failure, so an escalation of it to MEDIUM can arrive late. (d) A domain
  whose **first** observation is a failure produces the ordinary alerts once at the first cycle
  that answers (up to 9 for a domain with a full zone), as it did before this change. (e) A
  value carried over from a previous cycle shows as current in the snapshot and in the report
  until the DNS answers again: a marker for carried-over values is tracked separately. (f)
  **Operational note for whoever deploys it**: release this change together with the previous one
  (`RES-01`), never alone; before the rebuild, measure with read-only queries how many domains
  have the DNS not collected or undetermined (they will become `insufficient_data`) and how
  many baselines saved during past failures will produce a one-time alert; and call `/dns` inside
  the final image with the real `dig`. **Measured**: 468 new tests, only added to the existing
  files: 172 in `tests/test_classifier.py`, 153 in `tests/test_orchestrator.py`, 6 in
  `tests/test_dashboard.py` and 137 in the new `tests/test_col02_chain.py`. On the previous code
  of the three files that change, 175 fail; the 293 that pass are the controls (the true
  transitions that must still alert, the cases of determined absence, the malformed inputs, the
  fields that must stay identical). The chain test mocks none of our code: a spy on
  `subprocess.run` answers with the stdout of `dig`, in the format recorded with the real 9.18.39,
  to the real `/dns`, the real `_run_pipeline` and `_persist_intel`, the real classifier and a
  real `case_manager` on a scratch SQLite database. For each of 12 failures (SERVFAIL, REFUSED,
  connection refused and timeout on every query; SERVFAIL on the A, the MX, the NS, the TXT, the
  DMARC or the CAA alone; a malformed TXT; a bad packet on the CAA), ok, failure, ok gives 0
  alerts in the whole history, a snapshot after the failure equal to the one before, and a verdict
  of the failed cycle that is `insufficient_data` when A, MX, NS or the module is undetermined and
  the previous one otherwise; three closed cases (A and MX with a SERVFAIL on the A, parking with
  a SERVFAIL on the NS, a privacy-mail MX with a SERVFAIL on the MX) stay closed through the
  failure and the recovery; controls: an MX that is really gone (NXDOMAIN) alerts on the way out
  and on the way back, and a single lost packet, absorbed by `+tries=2`, gives 0. Independent
  verification: an oracle that computes the expected alerts from the outcomes of `dig` alone has 0
  mismatches over 12,240 cycles (397 of 720 on the previous code); 18,000 classifications without
  any `unknown`, and the snapshots and `/diff` payloads without any, are byte-identical to the
  previous code; 99 mutants of the fix, 72 killed, the survivors equivalent or gaps in the tests
  that are tracked separately. Security review: a matrix of 5,670 cells on the real
  `classify_variant`, previous code against this one, has 0 differences when every type answered
  or is NXDOMAIN; the only HIGH that falls is `mx_only_no_web` with the A alone `unknown` (12
  cells), LOW rises to MEDIUM only for the parking, for-sale, probable-third-party and
  probable-legitimate verdicts with A, MX or NS `unknown`, and every homoglyph rule stays HIGH; no
  new exception in 150,000 fuzzed inputs, 140,000 `/diff` payloads and 16 hostile snapshots. Suite
  1384 to 1852, 76.6 s (66.6 s with the previous commit, under the 90 s limit), 0 ruff violations.
  Full suite: 1852 passed, 1 skipped, 0 failed; ruff 0 violations.
- **`/dns` could not tell "the domain has no such record" from "the DNS did not answer": `dig
  +short` never prints the status of the response, so NODATA, NXDOMAIN, SERVFAIL and REFUSED
  were all an empty list (`RES-01`, core; first of the two changes of `COL-02`).** `dig_query`
  runs `dig +short`, which hides the `status:` of the response: NODATA, NXDOMAIN, SERVFAIL,
  REFUSED, FORMERR and NOTIMP all exit 0 with an empty stdout, and the transport failures that
  `COL-08` stopped turning into records were still "no record" once `is_valid` discarded them.
  A response whose TXT the parser rejects (a `;; Warning: Message parser reports malformed
  message packet.` line, a header that says `ANSWER: 1` and no answer line) was NODATA too. So
  `/dns` stored an unreachable DNS as "this domain has nothing", and its `error` field was a
  constant `None`, so `collection_failed` could never read the module as failed. Measured on
  the real chain (orchestrator, store, classifier) in a scratch directory, with the real `dig`
  9.18 in an isolated network namespace: one cycle of total DNS failure on a domain with a full
  baseline raised 6 false alerts on the way out (2 HIGH) and 9 on the way back (2 HIGH, 5
  MEDIUM), 15 per domain, and the baseline was saved degraded in every scenario.
  **The fix** is a new function, `dig_lookup(fqdn, rtype, timeout)`, in `shared/utils.py`, next
  to `dig_query`, which is unchanged with its tests. It returns `(status, records)`, with
  `status` one of `ok` (NOERROR with records), `nodata` (NOERROR without), `nxdomain` and
  `unknown`: "it could not be known", never a fact about the domain, always with no records. It
  asks `dig` for the header, with `+noall +comments +answer +nottlid +noclass` in place of
  `+short`. The options and the text of the two lines that are read (`;; ->>HEADER<<- opcode:
  QUERY, status: X, id: N` and `;; flags: … ANSWER: N, …`) are the same in `dig` 9.16, 9.18 and
  9.20 (read in the sources) and were recorded with the real 9.18.39. One process per query as
  before, same `+tries=2`, same timeouts, and the name guard of `SEC-26` runs first (a refused
  name starts no process and is `unknown`). The rules apply in this order and the first that
  matches decides, all giving `unknown`: an exception, a missing binary or a timeout; a
  non-zero exit status; a `;; Got bad packet` line; the parser warning above; anything but
  exactly one header line and one `flags` line; a number of answer lines different from
  `ANSWER: N`; an answer line with fewer than three fields. Then a whitelist: NOERROR and
  NXDOMAIN are answers, every other response code (SERVFAIL, REFUSED, FORMERR, NOTIMP,
  YXDOMAIN, NOTAUTH, the reserved ones, a token never seen) is `unknown`. It fails closed: a
  stdout without a header, such as the one of `+short`, is `unknown` and does not fall back to
  the old parsing, because that fallback is how a failure became data in `COL-08`. The lines
  are matched at their start: in presentation format an owner or an rdata that imitates the
  header or `Got bad packet` never starts with `;` (TXT and CAA come out in quotes, a `;` in a
  name is written `\;`), so it stays a record and cannot change the status. A record is the
  third field of the line, trimmed, without the trailing dot, sorted: the same text that
  `dig_query` gives for the same response (an NXDOMAIN keeps the CNAME chain, as `+short`
  did). Neither what `dig` printed nor the response code is repeated in the result.
  **What `/dns` returns**, additive only: `records_status` (the status of each of the 7 base
  types, also with `full=false`), `status` in `spf` (the TXT query), `dmarc`, `bimi` and `caa`,
  `dkim.selectors_unknown` and `subdomains.unknown` (not active, with the A or the CNAME
  `unknown`: different from "does not exist"). `error` is a constant text when all 7 base types
  are `unknown` and `None` otherwise. It is what makes `collection_failed` read the module as
  failed, so the orchestrator keeps the previous section instead of overwriting it, the rule
  that `CODE-01` already applies to the other modules. The text repeats neither the domain nor
  anything from `dig`. One `logger.warning` per request, with the number of `unknown` queries
  and the sanitized domain, lets whoever runs it see an outage without reading the JSON. Every
  field that existed is identical for the same `dig` responses (checked on the real chain,
  below). `dns_unknown_rtypes(dns)` reads the status for the consumers; a section without
  `records_status`, such as every snapshot already on disk, counts as known and reads as before.
  **Declared**: (a) **this is the first of two changes and it does not close the problem.**
  Alone it stops the false alerts of a **total** failure on the alert channel: 15 → 0 per
  domain in the chain above (verifier: 10 scenarios, 27 cycles). A failure of a single record
  type, which the response now marks `unknown` but nobody reads yet (measured: 1 HIGH on the way
  out and 1 on the way back), and the channel of the cases (a case can change classification
  without an alert in the history) behave as before until the consumers change; that is the
  second change, tracked as `COL-02`. (b) **Operational note for whoever deploys it**: release
  this change together with the second one, do not rebuild the container with this one alone;
  and before the deploy call `/dns` inside the final image with the real `dig`: if the format
  `dig` prints there differs from the recorded one (for instance a `~/.digrc` that adds
  `+short`), every query would come out `unknown`, which is safe but almost silent, visible
  only in the warning of the log and in `error`. (c) Deviation: `/dns` no longer passes the
  lists through `is_valid`, so a record whose text is the root or starts with `ERROR` no longer
  makes it discard the whole list of that query (before, one `NS` entry starting with `ERROR`
  hid the other nameservers); a bare root record is now returned as an empty string, a case
  tracked separately.
  **Measured**: 441 new tests, 303 in `tests/test_utils.py` (`TestRES01*`, on `dig_lookup` and
  `dns_unknown_rtypes`) and 138 in `tests/test_dns_intel.py` (the endpoint). The stdout of `dig`
  is the one recorded with the real 9.18.39 in an isolated network namespace (loopback only, a
  stub resolver): 54 cases, each with the `+short` output of the same response as the oracle,
  and further captures for imitated headers, rare response codes, a lost first attempt and
  transport failures; the few composed fixtures are declared as such, and two of them are
  checked against real captures. `subprocess.run` is replaced by a spy, so the suite starts no
  `dig` and uses no network. On the old code 435 of the 441 fail; the 6 that pass are the check
  of the fixtures and the controls that every existing field stays identical. Two helpers of
  `tests/test_dns_intel.py` (the `dig` spies of two older test classes) now answer in the
  format the argv asks for, the old stdout if it contains `+short` and the header format
  otherwise: 6 lines replaced, 0 assertions changed, and the 87 older tests of that file pass
  identically before and after. Independent verification: 115 scenarios with the real `dig`,
  the records equal to the `+short` oracle in 68 of 68, 150,000 mutations of the parser with no
  violation; 118 mutants of the fix, 94 killed, and of the 24 survivors 9 are equivalent, 11
  change output that `dig` does not emit and 4 are gaps in the tests, tracked separately.
  Security review: 31 hostile names with no process started, 43 scenarios with the real `dig`,
  12,300 hostile responses and 120,000 stdouts with injected lines, no violation (the parser
  failed closed every time), no output of `dig` in the JSON or in the log. Suite 943 → 1384,
  66.6 s (about 66 s before), 0 ruff violations. Full suite: 1384 passed, 1 skipped, 0 failed;
  ruff 0 violations.
- **`dig +short` writes its own diagnostics on standard output, and `dig_query` returned them as
  DNS records (`COL-08`, found by the `security-reviewer` while reviewing `SEC-26`).** When a
  query does not get a normal answer, `dig` prints lines such as `;; communications error …`
  or `;; no servers could be reached` on stdout, `+short` included, and tells it with its exit
  status. `dig_query`, where every DNS lookup of the services starts, took every non-empty line
  of stdout as a record and never read the exit status, and `is_valid` accepts any first line
  that does not start with `ERROR`: an error line was therefore a record, and a present one.
  Reproduced with the real `dig` 9.18 in an isolated network namespace (loopback only, a stub
  resolver), on three paths: the first UDP attempt is lost and the second is answered (exit 0,
  the true answer with the error line next to it); the DNS service refuses the connection
  (exit 9, 3 lines, 0.03 s); no network (exit 9, 4 lines, 0.02 s). A fourth path came out in the
  review of the fix, first tracked as `COL-10` and closed here: a response that `dig` cannot
  parse (for instance a malformed CAA forwarded verbatim by a resolver that does not validate)
  exits 0 with `;; Got bad packet: <reason>`, a byte count and a hexadecimal dump of the packet,
  and the dump lines do not start with `;`. **Effect downstream**, measured on the real chain
  (orchestrator, store, classifier) in a scratch directory: with the DNS unreachable, a domain
  with no records and an empty baseline raised 8 false alerts on the way out (A and MX from
  `[]` to the error lines, both HIGH, then NS, TXT, SOA, DMARC, BIMI and CAA) and 5 on the way
  back, with 18 of 18 DKIM selectors "found" and 25 of 25 subdomains "active"; the loss of the
  MX answer alone, on a domain with neither A nor MX, classified it `suspicious` / `high`; and
  the error text became the new baseline. The error line also contains the address of the
  resolver that the engine uses: it ended up in the response of `/dns` (156 occurrences in one
  full response, 234 diagnostic lines, 14,482 bytes) and, through the baselines, in the stored
  snapshots; now 0 occurrences (442 bytes). The fix is in `dig_query` only. A non-zero exit
  status (9 no answer, 10 fatal error, 1 usage, negative if a signal killed the process) returns
  a single entry `ERROR: dig exited with code N`, the shape the timeout already had, so
  `is_valid` is false and the DNS layer reads it as no record; with exit 0, a line that starts
  with `;; Got bad packet` returns `ERROR: dig got an unparseable response`; otherwise the
  stdout lines that start with `;` are dropped and the rest is returned as before. The messages
  never repeat what `dig` printed, so neither the resolver address nor the dump can leave.
  Exit 0 stays the status of every DNS answer, NXDOMAIN, NODATA, SERVFAIL and REFUSED included,
  whose stdout is empty: they remain "no records", not an error. Dropping the lines that start
  with `;` does not touch a record: in presentation format an rdata never starts with `;` (TXT
  and CAA come out in quotes, a `;` inside a name is written `\;`), checked with the real `dig`
  on 20 hostile rdata (13 with `;`, newlines and leading spaces, 7 that imitate the text
  `;; Got bad packet`): none starts with `;` and the genuine record survives. The arguments
  given to `dig`, the timeouts and the name guard of `SEC-26` are unchanged. **Behavior
  changes**, declared because they alter what the engine records: (a) a lookup that fails now
  counts as "no record", like the other DNS errors, instead of error lines counted as present
  records; after a cycle in which the DNS does not answer, when it comes back the domains that
  really have DMARC, BIMI and CAA get MEDIUM "return" alerts (3 per domain, measured), because a
  DNS error is still read as absence, a limit this fix does not touch and that is tracked
  separately; (b) **operational note for whoever deploys it**: the baselines already written
  with error lines are replaced by the clean values in the first cycle after the rebuild, with
  a one-time "changed" alert each; before the rebuild, count them with a read-only query on
  the snapshots and on the history (records that start with `;`), so the burst is expected.
  **Measured**: 90 new tests, 76 in `tests/test_utils.py` (`TestCOL08*`, on `dig_query`) and 14
  in `tests/test_dns_intel.py` (the endpoint); stdout and exit status are those recorded with
  the real `dig` 9.18 and `subprocess.run` is replaced by a spy, so the suite starts no `dig`
  and uses no network. On the old code 59 of the 90 fail; the 31 that pass are what it already
  did right and must keep: normal output unchanged (A, AAAA, MX, NS, TXT with inner `;`, CAA,
  SOA, CNAME followed by A), empty answers, the timeout and missing-binary errors, and records
  whose text imitates a diagnostic. Mutation testing by the independent verifier: 22 mutants of
  the first version of the fix, 10 killed, 3 equivalent, 9 survivors; the boundary tests added
  afterwards (negative exit status, lines between and after the records, indented lines, names
  with `\;`) kill 8 of the 9, and the last one only changes the wording of the error message,
  which the tests deliberately do not fix. 15 mutants of the corrective round: 7 killed, 6
  equivalent or irrelevant, and 2 not equivalent, killed by the 6 anchoring tests added at the
  end (3 failures each). Suite 853 → 943, about 66 s (about 65 s before), 0 ruff violations.
  Full suite: 943 passed, 1 skipped, 0 failed; ruff 0 violations.
- **A parameter of the unauthenticated `/dns` endpoint became the first characters of the
  name argument given to `dig`, and nothing limited how many of them a request could carry
  (`SEC-26`, found by the `bug-researcher` while tracing `SEC-24`).** `GET /dns` accepts
  `dkim_selectors`, a comma-separated list that replaces the default DKIM selectors; every
  entry was turned into `<selector>._domainkey.<domain>` and passed to `dig` as its name. The
  parameter had no pattern and no maximum length, and the code only split it on commas and
  stripped the spaces. But `dig` does not read every first character as part of a name: a
  leading `@` is the server to query and a leading `-` or `+` is an option. The process is
  started from an argument list with no shell, so no command could be executed this way; what
  could happen is that a query was redirected to a DNS server chosen by whoever calls the
  endpoint, with the answer reflected in the JSON of the response (reproduced with the real
  `dig` in an isolated network namespace, against a stub server on loopback), or that an
  option broke or altered the lookup. Separately, the number of selectors had no ceiling:
  each one is a `dig` process (up to 8 at a time, each lasting up to the DNS timeout plus
  10 s) and the HTTP parser accepts a value of about 64 KB, so one request could carry about
  32,000 short selectors, estimated at about 22 hours of work against a DNS that does not
  answer. The fix has two layers. At the entrance, `/dns` validates `dkim_selectors` before
  any `dig` is started, also when `full` is false (as already happens for `domain`): at most
  32 non-empty selectors, each one made of dot-separated labels as in the `selector` of
  RFC 6376 (letters, digits and inner `-`, 1-63 characters per label), and a value of at most
  2048 characters; otherwise 422 with a fixed message that does not repeat the input. Empty
  entries between commas and spaces around a selector are accepted as before, and the default
  list of 18 selectors is untouched. At the exit, `dig_query`, where every DNS lookup of the
  services starts its process, now refuses a name that is not a DNS name (empty, longer than
  253 characters, not starting with a letter, a digit or `_`, or containing anything outside
  letters, digits, `_`, `.` and `-`) and returns an error entry (`ERROR: invalid DNS name`, so
  `is_valid` is false) without starting the process, which also protects any future caller.
  For valid names the arguments given to `dig` are identical to before. **Behavior changes**,
  declared because they reject input that used to be accepted: a selector containing `_` or
  non-ASCII characters, more than 32 selectors, or a `dkim_selectors` value over 2048
  characters now gets 422; the check also runs with `full=false`, where the parameter used to
  be ignored whatever it contained; a name that is not a DNS name passed to `dig_query` gets
  an error without a process. The path used by the orchestrator, which never passes
  `dkim_selectors`, is unchanged: with `full` and `subdomains` it starts the same 78 `dig`
  processes with the same arguments and returns the same body as the old code, also on domains
  from 20 to 253 characters (real `dig`, checked by md5 of the body). Nothing changes on disk.
  **Measured**: 112 new tests, 73 in `tests/test_dns_intel.py` (the endpoint) and 39 in
  `TestSEC26DigQueryNameGuard` (`dig_query`); `subprocess.run` is replaced by a spy, so no
  real `dig` and no network is involved. On the old code 78 of the 112 fail; the 34 that pass
  cover behavior the old code already had and must keep (valid selectors reach `dig` with the
  exact name, the default list of 18, exactly 32 selectors and exactly 2048 characters still
  accepted, unchanged arguments for valid names). Mutation testing by the independent
  verifier, 61 mutants of the new code: 54 killed; the 7 survivors are not equivalent
  mutants but properties that the code does respect and no test checks yet (verified on the
  real code, tracked separately). Independent checks: `dig_query` fuzzed with 200,000 strings
  (every argument list that would be started carries a plain ASCII DNS name of at most 253
  characters), and 414 hostile plus 2,500 random requests against the endpoint, standalone
  and mounted in the unified app, with the same outcome in both. **Worst case**: before, up to
  about 32,000 selectors per request, about 22 hours estimated with a DNS that does not
  answer; now 32 selectors, and the DKIM stage is bounded in the order of 80 s (8 at a time,
  20 s each). The overall duration of a request with the new limits is of the same order as
  the orchestrator's default path. Suite 741 → 853, about 65 s (about 66 s before), 0 ruff
  violations. Other limits of this endpoint are tracked separately. Full suite: 853 passed,
  1 skipped, 0 failed; ruff 0 violations.
- **The optional live TLS inspection of `/cert` opened its connection with no SSRF guard and
  with a timeout per address but no limit on the whole call (`SEC-25`, found by the
  `bug-researcher` while tracing `SEC-24`).** `GET /cert?tls_live=true`, on the
  unauthenticated engine side, calls `inspect_tls` to read the certificate that the
  lookalike domain is serving right now. `inspect_tls` connected with a plain
  `socket.create_connection`: the address finally contacted was never checked, so a
  lookalike whose DNS answers with an internal address was connected to from the engine's
  own network position, and the 10 s timeout applied to each address returned by the
  resolver separately, so a name with several unresponsive records held the request for as
  many times the timeout as records the owner of that DNS chose to publish. They are the same
  two defects that `SEC-24` and `SEC-18` had closed for `http_get_with_retry`, left behind in
  a second code path that carried its own copy of the connection. Fix makes `inspect_tls` use
  the same connection function as `http_get_with_retry` (`_FetchDeadline.create_connection`):
  the name is resolved once, every address returned is validated before the first connect,
  one blocked address blocks the whole host (no connection is attempted, not even to the
  public ones), and the address contacted is the one that was validated. The block comes back
  in the usual result shape (`connected` false, `certificate` none, `error` starting with the
  existing SSRF prefix), with no retry; it follows `SSRF_PROTECTION` (off = no block, for
  offline labs). The whole call, every connect and the handshake included, is bounded by
  `MAX_FETCH_SECONDS` (40 s by default, read at run time); the per-operation `timeout`, the
  port, the SNI and the certificate hash returned for a public address are unchanged. The
  watchdog thread that enforces the limit is stopped on every exit (success, block,
  expiry), and if it cannot be started the call returns an error without connecting. Nothing
  else in the `/cert` response changes and nothing changes on disk: the pipeline never passes
  `tls_live`, so no persisted data goes through this path. **Measured**: 18 new tests
  (`TestSEC25InspectTlsGuard`; resolver and `connect` are simulated, the TLS server is local
  with a certificate generated at run time, no real connection to a non-loopback address);
  on the old code 11 of the 18 fail, and the 7 that pass either cover behavior the old code
  already had (public address unchanged, opt-out, SNI, requested port, per-operation timeout)
  or cannot fail without the new watchdog (no thread left alive after success or expiry).
  Mutation testing by the independent verifier, 14 mutants of the new code: 13 killed, the
  survivor is equivalent (a branch that cannot be reached with certificate verification
  disabled); a first round left 5 alive, which is where 7 of the 18 tests come from. With 8
  unresponsive addresses a call that took 80.11 s now returns in 40.01 s. Suite 723 → 741,
  about 66 s (from about 64 s), 0 ruff violations. **Known limits, not changed here**:
  `GET /cert?tls_live=true` can last up to about 80 s in a single request, because the
  Certificate Transparency lookup and the TLS inspection run one after the other and each has
  its own 40 s limit (the pipeline does not use `tls_live`); certificate verification stays
  disabled on purpose, since only the DER hash is read; other limits of this path are tracked
  separately. Full suite: 741 passed, 1 skipped, 0 failed; ruff 0 violations.
- **The SSRF guard validated a host name, but nothing validated the address the connection
  actually reached, so the guard could be bypassed — and the list of blocked networks had
  holes (`SEC-24` + `SEC-21`, merged into one change because one check closes both; found by
  the `security-reviewer` while reviewing `SEC-18`).** The guard in front of
  `http_get_with_retry` (`is_safe_url`) read the host out of the URL with one parser and
  resolved it on its own; the connection layer then read the URL again with a different
  parser and resolved the name a second time. Nothing checked the address finally passed to
  `connect`, so a difference between the two readings, or between the two resolutions, was
  enough to get around the guard on the unauthenticated `/http` path, where the names fetched
  are lookalike domains and the DNS that answers for them belongs to whoever is being
  investigated. Two defects of the block list itself came with it: `_is_blocked_ip` did not
  cover some networks that are not publicly routable, and for an IPv4 address mapped into IPv6
  it gave different answers depending on the Python version (including a false positive on a
  public address on 3.12). Fix moves the check to where it cannot be circumvented:
  `_FetchDeadline.create_connection`, the connection function introduced by `SEC-18`, now
  resolves the name **once**, validates **every** address returned and connects to those same
  addresses, so the address that was checked is the address that is contacted — on both the
  `requests` branch and the `urllib` fallback, at every hop. One blocked address blocks the
  whole host, exactly as the check by name does: if any answer is internal no connection is
  attempted, not even to the public ones. The block is the existing SSRF error, terminal (no
  retry), raised through a dedicated exception that is not an `OSError`, because urllib3 and
  `urllib` would otherwise turn it into a retryable connection error. It follows
  `SSRF_PROTECTION` (off = no block, for offline labs). `_is_blocked_ip` now also blocks
  `100.64.0.0/10` (carrier-grade NAT) and `192.88.99.0/24` (6to4 relay anycast), and judges an
  IPv4-mapped IPv6 address by the IPv4 it encapsulates, with the same answer on 3.12 and 3.13.
  The connection to a proxy configured by the operator through the environment is exempt: it
  is a trusted endpoint, and the guard would otherwise validate the proxy's address instead of
  the target's. **Measured**: 67 new tests (`TestSEC24ConnectTimeIpGuard`; resolver and
  `connect` are simulated, no real connection to a non-loopback address), suite 656 → 723,
  about 64 s (from about 61 s), 0 ruff violations; on the old code 31 of the 67 fail, and the
  36 that pass are the invariants (public address unchanged, opt-out, proxy, blocks that
  already existed). Mutation testing by the independent verifier, 34 mutants of the new code:
  28 killed, the 6 survivors are equivalent. An address matrix of 93 entries — 50 that must be
  blocked (the boundaries of every blocked range, mapped forms), 22 public neighbours that
  must pass, 21 informational — gives 0 misses and 0 false positives on Python 3.11, 3.12 and
  3.13. **Behavior change to know about**: a name that resolves into one of the newly blocked
  networks now gets the SSRF error instead of a fetch, and `collection_failed` reads that
  error as a real reading, as it does for the check by name, so the `http` section of such a
  domain stops being "fetched"; a transient, anomalous DNS answer is read the same way
  (tracked separately; noise limited to the domain that causes it). **Operational note for whoever
  deploys this**: before the rebuild, count with a read-only query on the snapshots in `/data`
  how many monitored domains resolve into `100.64.0.0/10` or `192.88.99.0/24` — their `http`
  section will be rewritten on the first cycle after the deploy. Nothing else changes on disk:
  no format, no migration. **Known gaps, tracked separately**: the fallback `urllib` branch
  (unused with the pinned `requests`) and connections through a proxy configured in the
  environment (no compose file defines a proxy); other outbound connection paths are
  hardened separately; the block list is a deny-list and so not exhaustive; and the guard
  hooks into the same non-public attributes of `requests`, `urllib3` and `http.client` as the
  `SEC-18` limit, so a dependency upgrade has to re-run these tests. Full suite: 723 passed,
  1 skipped, 0 failed; ruff 0 violations.
- **`http_get_with_retry` only had a timeout per socket operation, re-armed on every byte, so
  a server answering one byte at a time held a thread for as long as it liked — in the
  unauthenticated zone (`SEC-18`, found by the `security-reviewer` while reviewing
  `SEC-16`).** `timeout=` reaches `requests` (and `urlopen`) as a per-operation timeout:
  `requests` turns the scalar into `urllib3.Timeout(connect=t, read=t)`, never `total`, and
  `read` applies to each `recv()`, so it re-arms with every byte received while the read loop
  had no clock of its own. `/http` fetches attacker-controlled lookalike domains, and the same
  hole existed in the headers, in each of the up-to-5 redirect hops and in the retry loop.
  Reproduced on a local server (SSRF guard bypassed only inside the probe process): a body
  dripping 1 byte/s with `timeout=2` took 4 / 9 / 19 s for 5 / 10 / 20 bytes; headers plus
  body, 39 s for 40 bytes; 5 redirect hops, 34 s (the times add up); 3 attempts of a dripping
  503, 56.5 s (the times multiply, plus backoff). At 1 byte every 2 s the 2 MiB cap of
  `SEC-16` is reached after about 48 days. Under `unified.py`, where every endpoint shares
  anyio's thread pool, 40 concurrent dripping `/http` calls took `/health` from 0.003 s to
  5.74 s; and when a client gave up after 1.5 s, +49 threads stayed alive on the server (the
  orchestrator abandons `/http` after 45 s, the server-side thread does not go away). The
  connect phase leaked time too: with several A records, urllib3 tries every address with the
  full timeout, so 5 dead records at `/http`'s real parameters (`timeout=15`) held a call for
  231 s. Fix puts **one limit on the whole call** — attempts, redirects, backoff, the connect
  to each address and the TLS handshake: 40 s by default, set with the `MAX_FETCH_SECONDS`
  environment variable (validated as a finite number > 0; anything else falls back to 40 with
  a warning that names the variable, same principle as `PERF-01`, so a typo cannot stop the
  platform from starting) and with a `max_seconds` parameter per caller, which takes
  precedence over the constant in both directions and follows the same rule. 40 s because it
  sits under the orchestrator's 45 s `SERVICE_TIMEOUT`: the thread is freed before the
  pipeline gives up, and anything arriving after 45 s was already being discarded. The
  mechanism is a single clock per call plus a watchdog thread that does no I/O: when the
  deadline passes it `shutdown`s the sockets the call has opened (and keeps doing so every
  50 ms for sockets registered late), which wakes the blocked `recv`. The request itself stays
  on the caller's thread, so no work is abandoned, and the watchdog is stopped and joined in a
  `finally` on every exit path. A clock check between chunks would not have worked — with a
  declared `Content-Length`, `read(8192)` blocks until 8192 bytes arrive — and
  `urllib3.Timeout(total=)` sets `settimeout` once, statically (measured: 7.00 s for a 3 s
  `total` against a drip). Each address of `getaddrinfo` is tried with the time that remains,
  the TLS handshake starts from the remainder left after the connect, and the backoff is capped
  to what is left. A `timeout` given as `None`, as a `(connect, read)` tuple or as an
  `urllib3.Timeout` keeps working as before, each component limited to the remainder (two
  regressions of that contract, introduced by the first revisions, were caught in review and
  closed before this commit). **When the limit is hit** the call returns the error
  `fetch deadline exceeded: 40s` with `status_code`, `content`, headers and `final_url` all
  empty — nothing partial, not even the status of an earlier hop or attempt — so
  `collection_failed` reads it as "I could not look" and the baseline is not poisoned (the
  `CODE-01` class); checked end to end from the expiry to `collection_failed` to the
  classifier, with no demotion of the case (`CODE-15`). If the watchdog thread cannot be
  started the function returns an error dict and makes no request, instead of running
  unbounded. **Measured**: 40 concurrent dripping `/http` calls against `unified.app`,
  `/health` held up 13.05 s on the old code and 2.04 s with the limit set to 3 s (the `/http`
  calls themselves 14.02-14.07 s → 3.02-3.07 s, no thread left over 2 s after the client
  leaves, against 20 workers alive for the whole drip before); with 8 dead A records per
  call, 23.08 s under the first revision of the fix → 2.03 s; at the real parameters
  (`timeout=15`, limit 40 s) 5 dead A records: 231.18 s before, 40.01 s now (also 40.01 s
  with 10). A real TLS server (self-signed certificate) dripping the body, the headers or the
  handshake is cut at 2.00-2.02 s with a 2 s limit, on both the `requests` branch and the
  `urllib` fallback. Suite 590 → 656 tests (66 new, with real waits), 0 ruff violations; on
  the old code 53 of the 66 fail, and the 13 that pass are the invariants the fix must
  preserve (fast and slow-but-in-time responses, SSRF guard, size cap, the `timeout` forms
  that already worked). Mutation testing by the independent verifier, 64 mutants at the last
  round: the 16 the reviews flagged as meaningful are all killed, the survivors being
  equivalent or low-severity branches no test pins (tracked separately). **Behavior change
  to know about**: a legitimate response that takes longer than 40 s — a slow crt.sh, say —
  now fails and the pipeline treats it as a failed collection; before, the orchestrator
  discarded it anyway past 45 s, so the practical change is the 40-45 s window, and the worst
  legitimate case drops from 51 s (`/http`, 3 × 15 + 2 + 4) and 62 s (crt.sh, 2 × 30 + 2) to
  40 s. Callers that really need longer pass `max_seconds`. The 40 s of fetching sits on top of
  the HTML analysis inside the same 45 s. Suite time goes from about 32 s to about
  61 s: the `SEC-18` tests use real waits (the limit is scaled down to 0.5 s in them).
  **Known gaps, not fixed here**: `getaddrinfo` cannot be interrupted, so a slow name
  resolution overshoots the limit by up to one resolution (+4 s measured); calls through a
  proxy set in the environment are not fully covered (the CONNECT tunnel, and TLS-in-TLS via
  an HTTPS proxy, sit outside the limit; no compose file defines a proxy; tracked
  separately); the `urllib3>=2,<3` pin is looser than the `SEC-16` decompression guard needs
  and has to be tightened (preexisting, tracked separately); the limit hooks into a few
  non-public attributes of `requests`, `urllib3` and `http.client`, verified on the pinned
  `requests==2.32.3`, so a dependency upgrade has to re-run the `SEC-18` tests; passing
  urllib3's own `Timeout.DEFAULT_TIMEOUT` sentinel as `timeout` (no caller does) raises
  `TypeError` where it used to work (tracked separately). Further SSRF hardening of the fetch
  path is tracked separately.
- **Markup hidden in the fallback content of a regularly closed `<iframe>` — an `<iframe>`,
  `<form>` or `<img>` pointing at an external host — was discarded by the hidden-element
  detector with zero findings (`CLS-01z`; absorbs `CLS-01w`, the "known, declared detection
  gap" of `CLS-01j`/`CLS-01q` below).** The content of a closed `<iframe>` is `RAWTEXT`: a
  browser never renders it. `_TagCollector` already marked it opaque and `_collect_tags`
  dropped opaque tags, so an `<img src="https://evil.example/c2">` carried there contributed
  nothing to `risk_indicators` and raised no alert — a total false negative that costs one line
  to reproduce. Fix recovers those tags from the existing collector (`_TagCollector` is
  bit-identical, no new grammar, no new parse of the document) and exposes them as a new
  category, `suspicious_dead_markup`: **weight 30** in `risk_indicators` (user decision), a
  CRITICAL alert `legit_suspicious_dead_markup_detected` when it is found on the client's
  *legitimate* domain (same channel as `hidden_forms`/`invisible_iframes`, so it does not widen
  the split between alert severity and case severity) and, through the existing
  `hidden_risk >= 30` rule, a `suspicious`/`HIGH` case on a lookalike. "External" means an
  absolute host that is neither the client domain, nor one of its subdomains, nor in
  `_DEAD_MARKUP_CDN_WHITELIST` (kept separate from the list `external_resources` uses).
  Findings are capped at 20 and the loop stops at the twentieth instead of slicing afterwards,
  so the work is bounded, not only the output. Eight preexisting `CLS-01j`/`CLS-01q` tests
  asserted `risk_indicators == 0` for exactly this case (their own docstrings called it the
  open gap); they were reconciled to the new behavior, keeping every assertion on the live
  channel and on `never_closed`. **How it got here**: the first four review rounds each
  rejected it, the fifth passed the code and failed the tests, and a test-only round (5b) was
  confirmed. The first design also covered a further family of hidden markup; review showed it
  counted one element twice and was too costly on large hostile pages, so on the user's decision
  that family was removed and is tracked separately. The CDN allow-list started as fragments (`fonts.`,
  `fontawesome`) and was rejected at round 3 — `fontawesome.xyz` and `fonts.evil.example` both
  evaded it; round 4 anchored it to full hosts (`use.fontawesome.com`, `kit.fontawesome.com`,
  `fonts.shopifycdn.com`, plus the registrable domains), matched by suffix on a dot boundary
  only. The round-4 verifier then found that the host was still pulled out with
  `https?://([^/]+)` instead of the URL grammar a browser applies, so a single character
  bypassed both the allow-list and the client-domain exclusion — `#`, `?`, `\`, `user:pw@`, a
  protocol-relative `//host`, leading whitespace (**7 PoCs out of 7 scored risk 0**,
  reproduced end to end). Round 5 replaces the regex with `_dead_markup_url_host`, a
  WHATWG-conformant host extraction in stdlib only (`urllib.parse.urlsplit` was evaluated and
  rejected: it diverges on `\`, on extra slashes and on `http:host`): C0 controls and spaces
  trimmed at the ends, tab/LF/CR dropped everywhere, `\` read as `/`, authority ended at the
  first `/ ? #`, host taken after the *last* `@`, bracketed IPv6 handled apart, port and one
  trailing dot dropped. Two product decisions: `//host` is external (user, 2026-10-21), and so
  is `http:host` with no slashes — which WHATWG reads as a relative path on an `http` page, but
  the detector does not know the page's scheme, so it is a declared fail-safe false positive.
  The round-5 review passed the code and found 12 non-equivalent mutants that no test killed;
  round 5b adds the tests that kill them. Rounds 1-4 were committed ahead of their
  closing review on the user's decision and without a changelog entry; this entry covers them
  together with rounds 5 and 5b. **Measured**: suite 464 → 590 tests (+53 for round 5, +73 for
  round 5b), 0 ruff violations; the 53 round-5 tests fail 26 on the round-4 code, the 73
  round-5b tests fail 32 on it (the rest are guards that pin behavior the mutants would
  change), all green after. Against the browser's own parser as oracle (`new URL()`, Node 22,
  `https` and `http` base): **0 false negatives on 2.64 million URLs** (verifier, four
  generators independent of the fixer's) and on about 6 million more (security-reviewer:
  random, exhaustive and per-character corpora; its generator finds 71,953 false negatives in
  400,000 URLs on the round-4 code and 0 here). In real Chromium with request interception: **0 requests
  to an external host out of 120,000 URLs the detector did not flag**, against 949 external
  contacts out of 3,000 it did (positive control). Mutation testing: of 54 mutants of the new
  code, the 12 non-equivalent survivors of round 5 are all killed by the round-5b tests; 4
  equivalent mutants remain. Cost on the worst case — 2 MB of dense external dead markup,
  best of 5 (verifier): 0.83 s before `CLS-01z`, 1.25 s after round 4, 0.95 s now.
  **Known gaps, not fixed here, tracked separately**: further forms of hidden markup that this
  detector does not cover; host extraction elsewhere in the analysis that does not use
  `_dead_markup_url_host`; and the cost of `detect_hidden_elements` on attacker-controlled
  bodies in the unauthenticated zone, which rounds 1-4 raise by about 30% on the worst case
  measured (the collector now tracks iframe/form/img targets; round 5 adds nothing to it).
  Also accepted, in the family of
  fail-safe false positives: URLs the browser rejects as invalid, obfuscated spellings of the
  client domain or of a CDN (percent-encoding, fullwidth, zero-width space), and `http:host`;
  and a literal `www.` host is no longer flagged (it was after round 4; unreachable, there is no
  TLD `www`). **Operational note for whoever deploys this**: the baselines stored in `/data`
  were computed by the old detector, and `_diff_hidden_elements` raises its alert when
  `risk > prev_risk`. On the first cycle after a rebuild that ships this code, every client
  page that *already* contains external dead markup will score 30 above its baseline and
  produce a CRITICAL `legit_suspicious_dead_markup_detected` alert for content that was there
  all along — and round 5 catches more forms of it (`//host`, the one-character bypasses) than
  rounds 1-4 alone. That is the new detector working as designed, not a new threat; how many
  pages are affected has not been measured. Decide before the rebuild whether to announce it in
  the release note or to re-baseline first. Full suite: 590 passed, 1 skipped, 0 failed; ruff
  0 violations.
- **`http_get_with_retry` downloaded an HTTP response body of unbounded size, in the
  unauthenticated zone, with no rate limit (`SEC-16`, found by the `security-reviewer` while
  reviewing `CLS-01z`).** `/http` fetches attacker-controlled lookalike domains — nothing
  caps the size of what they can return. Reproduced: a single `/http` call against a 5 MB
  response took 16.44s wall-clock (up to 19-23s with `check_www=True`, 4 GIL-serialized
  fetches), with the cost scaling linearly with body size and no upper bound — a cheap DoS
  against a service with no authentication in front of it. Fix switches both download paths
  (`requests`, and the `urllib` fallback used when `requests` is unavailable) from a single
  blocking read to streaming (`stream=True` + `resp.iter_content(chunk_size=8192)`, or
  `resp.read()` in bounded blocks for the fallback), stopping as soon as the accumulated body
  reaches `MAX_FETCH_BODY_BYTES` — the byte past the cap is never read off the socket, not a
  post-download truncation. New module constant, default 2 MiB (`2*1024*1024`), configurable
  via the `MAX_FETCH_BODY_BYTES` env var, same pattern as `shared/security.py`'s
  `MAX_BODY_SIZE` and `services/cert_intel.py`'s `MAX_CRTSH_BYTES`. `cert_intel.py` now passes
  its existing 10 MB `MAX_CRTSH_BYTES` explicitly as `max_bytes` to the shared function instead
  of duplicating a second, unreachable size check after the fact (removed dead code). Two
  rounds of independent review surfaced two follow-on defects, both closed in the same pass
  before commit: (1) a connection leak — `resp.close()` was only reached when the streaming
  loop exited normally, so a connection that broke mid-transfer (`IncompleteRead`, read
  timeout) never released its socket; now wrapped in `try/finally` around the streaming loop
  alone, so success, cap-reached, and exception paths all close exactly once. (2) a
  decompression-bomb gap — capping the *decompressed* body only bounds the final `content`,
  not the peak memory of a single `iter_content` chunk; on `urllib3<2` a single chunk can
  materialize several MB of decompressed data before the loop ever gets to check the cap
  (measured ~8.4 MB peak on 1.26.20 for a body compressed ~1:20, vs. ~8192 bytes on the pinned
  2.7.0 — over 250x). `requirements.txt` now pins `urllib3>=2,<3` (a valid subset of the range
  `requests==2.32.3` already requires), which is the actual defense — the guardrail test spies
  on `iter_content` to assert the per-chunk peak stays bounded, and only catches a future
  regression of the pin itself, not a first-time absence of one (an assertion on the final
  truncated `content` would always be green by construction, which is why the first version of
  that guardrail test was rejected on independent review and rewritten to observe the
  per-chunk peak instead). Full suite (SEC-16 in isolation, re-measured against a clean
  worktree): 437 passed, 1 skipped, 0 ruff violations.
- **A homoglyph domain's severity was decided by its content, never by its form (`SCO-05`,
  found by `bug-researcher` while investigating `SCO-03`).** `_classify_by_rules`
  (`services/classifier.py`) never read `v.fuzzer`: a domain flagged by dnstwist as
  `homoglyph` — an intentional lookalike character substitution, `examp1e.example` for
  `example.example` — fell through to the same generic rules as any other variant, and an
  omograph with active-looking content (a real HTTP response, a certificate) came out
  `legitimate_probable`/`LOW` regardless of the substitution in its name. Fix adds a
  dedicated block: script-mixing within a single label (Latin + Cyrillic/Greek/other, after
  punycode decoding and NFKC normalization) or a non-`aged` domain that is either resolving
  or dormant-with-no-signal is now classified `suspicious`/`HIGH` — never `CRITICAL` from
  name alone, keeping the two severity channels consistent. **6 input→outcome
  cases** from the accepted criterion now covered end to end, on real
  snapshots (anonymized) for the domains where the shape matters: content-vs-form on a
  resolving non-aged omograph, an aged control (unchanged, `predates_campaign` already
  covered it), a WHOIS attempted-and-failed control (must **not** elevate — "couldn't look"
  is not "saw something bad"), script-mixing, a dormant non-aged omograph, and a
  non-homoglyph fuzzer control. A residual mechanism (`WHOIS_ONLY_DOMAINS`, opt-in via
  `.env`, default empty) lets the operator request a WHOIS-only lookup for permanently
  dormant omographs that never reach the normal gather path, with an in-process 30-day
  cache keyed per-tenant so two clients monitoring related brands never cross-serve each
  other's WHOIS. **Restricted after the fix first shipped**: the Latin+Han/Kana exception
  added to keep genuine Japanese business names (`bicカメラ`, BIC CAMERA) out of the
  script-mixing rule was too broad — it exempted *any* Latin+Han/Kana label, including one
  carrying a single Han/Kana character that is a visual confusable of a Latin letter
  (`g口口gle-mail.com`, PoC from independent verification). Narrowed to a curated list of
  Han/Kana characters that are visual confusables of Latin letters; extending that list is
  tracked separately. Also fixed in the same pass: `collection_failed`
  (`shared/utils.py`) treated a WHOIS record with `error: ""` (present but empty — the shape
  `sanitize_error()` produces from an exception with no message) as a successful lookup,
  the same "absent ≠ failed" defect class as `CODE-01` but on the value instead of the key —
  checked against **every snapshot of a real dataset**, none carry an empty-but-present `error`,
  so the stricter predicate does not reclassify any existing case. Full suite: 424 passed,
  1 skipped, 0 ruff violations.
- **The collection-failure guard added by `CODE-23` discarded the reasoning of the rule it
  overrode, so an analyst lost the "why" behind every domain the guard demoted (`CODE-30`,
  found by the `verifier` at G6 of `CODE-23`, introduced by that fix, not preexisting).**
  `_apply_collection_guard` built a brand-new result from scratch when it overwrote a
  verdict with `insufficient_data`: `known_parking_ns` might have already explained "NS on
  a known parking provider", or `http_active_substantial_content` "active site with
  substantial content" — the guard replaced all of it with a generic "collection failed
  for: cert — no observable signal", with no trace of what the rule cascade had actually
  found. Fix: `_apply_collection_guard` now appends the underlying rule's name and rationale
  to the guard's own message (`" — would have matched: <rule> (<rationale>)"`) instead of
  discarding them, skipping the append only for `no_matching_rule` (nothing to record). The
  combined string is capped at 500 characters (`_GUARD_RATIONALE_CAP`, same order of
  magnitude as the existing cap on attacker-influenced text fields, `_cap_ioc`,
  `shared/utils.py:514-523`) — the cap applies to the *entire* string, template included, not
  just the appended tail, after a first round caught the template itself (`failed_sections`,
  built from unvalidated `collection_status` keys) overflowing the cap before the append
  logic ever ran. **Measured on a set of real snapshots, two independent runs**: of the guard
  activations, **none carried a restored rule/rationale before this fix, 98% do
  after** (the rest are legitimate `no_matching_rule` cases with nothing to restore),
  zero cap violations, maximum observed rationale length 432/500 characters. **Known gaps,
  not fixed here, tracked separately**: input validation on the classifier endpoint, which
  this fix's cap bounds but does not replace, and the filtering of control characters upstream
  of this rationale (preexisting; this fix only widens the reachable path). Full suite: 384
  passed, 1 skipped, 0 failed; ruff 0 violations.
- **A domain with a genuinely failed `cert`/`whois` lookup could still come out as a
  whitelist candidate, because the positive classification rules ran *before* the
  collection-failure guard and simply returned first (`CODE-23`).** The guard introduced
  by `CODE-15`+`CODE-14` sat at the *bottom* of `classify_variant`, reached only when no
  rule matched. Any rule that fired earlier — `parking`, `for_sale`, `legitimate_probable`,
  `likely_third_party`, and every `needs_review` variant — returned before the guard was
  ever evaluated, even when whois/cert/reputation had genuinely failed that cycle: a domain
  with `cert` unreachable and `whois` empty, but a substantial `http` response, exited as
  `legitimate_probable` instead of flagging that a third of its evidence was never
  collected. Fix: `classify_variant` now runs the full rule cascade first
  (`_classify_by_rules`, unchanged — same order, same thresholds, same conditions) and then
  applies the guard to *whatever* result came out (`_apply_collection_guard`), overwriting
  it with `insufficient_data` when whois/cert/reputation failed. **Criterion set by the
  user (2026-08-05): "I couldn't look" must never silence "I saw something bad", but it
  must stop the system from saying "looks fine" with half the data missing** — so the
  overwrite has exactly one exception: `suspicious` (`HIGH` case severity, the only
  category ranked above `insufficient_data`/`MEDIUM`) survives the guard unchanged; every
  `LOW`- and `MEDIUM`-ranked verdict yields to it. `cert` (crt.sh) is the section that
  actually failed in **98% of the guard-eligible snapshots** of a set of real snapshots
  — the same crt.sh instability `CODE-01` and `CODE-26` already trace back to.
  38/19 lines in `services/classifier.py`, 131 lines of new regression tests (5 red cases,
  one per absolutory category, plus 3 non-regression checks — the one that matters is that
  a domain flagged `suspicious` via `mx_only_no_web` with `cert` failed stays `suspicious`,
  not `insufficient_data`). Full suite: 374 passed, 1 skipped, 0 failed; ruff 0 violations.
  **Operational note for whoever opens the dashboard after the first rescan with this change**:
  measured on a set of real snapshots, `insufficient_data` went from **under 2% to about a
  third of the domains (33%)**, and **about one domain in ten, until then a whitelist
  candidate, changes outcome** to `insufficient_data`. That jump is the fix working as
  intended, not a new instability in the pipeline — those domains were never actually vetted,
  they just looked vetted because a positive rule answered before the failed lookup was
  checked. **Known gaps, not fixed here**: the set of categories that survive the guard is a
  hand-maintained literal, `{"suspicious"}`, instead of being derived from the severity
  ranking the design actually specifies — a future `CRITICAL` rule not added to that set would
  be silently downgraded by a collection hiccup (tracked separately); and `CODE-30` (the guard
  overwrites `rule` and `rationale` too, so the domains whose classification changes lose the
  record of *which* rule would have matched — "looked like parking, but `cert` failed" becomes
  a generic "collection failed for: cert").
- **A collection failure could reopen a case an analyst had already closed (`CODE-26`).**
  `CODE-15`+`CODE-14` (below) made `insufficient_data` — emitted when crt.sh is
  unreachable, a VT quota is exhausted, or any other enrichment source fails to
  respond — carry severity `MEDIUM` instead of `LOW`. `case_manager.ingest_case`'s
  closed-case escalation guard (`:575-611`) compared only `SEVERITY_RANK`, so on a
  case closed at `severity_at_detection='LOW'` a bare `MEDIUM` from a dead crt.sh
  outranked it and put the case back in front of an analyst — infrastructure noise
  read as new evidence, with zero action from the domain owner. Fix: the escalation
  check now excludes `insufficient_data` explicitly
  (`COLLECTION_FAILURE_CLASSIFICATION`, `case_manager.py:71,599`), regardless of its
  rank. **The discriminant is the classification, not the severity**, deliberately:
  `needs_review`/`MEDIUM` carries the exact same rank as `insufficient_data`/`MEDIUM`
  but is a genuine re-classification of the domain, not a collection gap, and must
  keep reopening the case — a fix that filtered on severity instead would have
  silently swallowed that case too, and is exactly what the regression suite for
  this ID was built to catch (`TestClosedCaseInsufficientDataNoReopen`, 6 tests).
  Measured exposure on a real dataset: the closed cases all sat at
  `severity_at_detection='MEDIUM'`, so the spurious-reopen count was **zero** —
  but **most open cases sat at `LOW`** (`legitimate_probable`, `parking`,
  `for_sale`, `likely_third_party`) and each becomes reopenable by the next
  collection hiccup the moment it's closed as a false positive, which is the routine
  disposition for exactly those classifications. The trigger isn't rare: `cert`
  (crt.sh) failed on **about 28%** of the real snapshots measured. 12/1 lines in
  `services/case_manager.py`, 110 lines of new regression tests. Full suite: 366
  passed, 1 skipped, 0 failed; ruff 0 violations. **Known gaps, not fixed here, tracked
  separately**: the guard constant isn't shared with the producing literal in
  `classifier.py`, so an independent rename on either side silently reopens the
  exposure with no error; and a suppressed reopen — for insufficient
  rank as before this fix, or now for this guard — still writes nothing to the
  audit log (pre-existing, not introduced here, but this guard now rides on that
  silence to enforce a security decision). **Release condition**: `CODE-15`+`CODE-14`
  (below) was accepted with this gap known and must not be released without this change.
- **A collector that attempted and failed to gather data produced the same verdict as one
  that looked and genuinely found nothing (`CODE-15` + `CODE-14`, reunified).**
  `classify_variant` had no way to tell "whois/cert/http/reputation was queried and the
  source failed" from "queried successfully, nothing there" — both collapsed into
  `needs_review`/`no_matching_rule` with an unqualified `low` confidence, so an analyst
  reading the case could not distinguish a genuine dormant domain from a domain nobody
  could actually look at that cycle. Fix: `orchestrator._build_collection_status` builds a
  `{section: bool}` failure map once per cycle, from the same `_module_failed` used for the
  alert/baseline channel (`CODE-01`/`CODE-14`), and propagates it to the classifier as
  `VariantInput.collection_status` at both call sites (`orchestrator.py:387-392` and
  `:497-503`); the classifier now reads that map instead of re-inspecting the raw collector
  dicts, and returns `insufficient_data` when a qualifying section failed.
  `shared.utils.collection_failed` becomes the single source of truth both channels share
  for "did this module actually produce data", reading the real failure shapes of
  `reputation.py` (`error` stays `None` even when VT/OTX/SecurityTrails all fail — `CODE-14`)
  and `http_fingerprint.py` (`overall_status` in `("down", "error")`, not `error`).
  Two user decisions shaped the final criterion, both reached after adversarial review found
  the first attempt exploitable: **(2026-08-02)** a failed `http` alone does not downgrade —
  `http` is the only section an attacker can fail on command (cloaking the scanner via
  IP/user-agent blocklisting, standard in phishing kits), while whois/cert/reputation depend
  on third-party infrastructure outside the attacker's control; downgrading on `http` alone
  would have handed the attacker a free deprioritization on exactly the domains that deserve
  the most scrutiny. **(2026-08-04)** `insufficient_data` no longer maps to `LOW` severity —
  it stays `MEDIUM` (`orchestrator.CLASSIFICATION_SEVERITY`) — because the LOW mapping
  downgraded a case on the mere failure of one optional module (`cert` via crt.sh,
  historically unstable; `reputation` on VT/OTX/SecurityTrails quota exhaustion during a
  high-volume dnstwist scan) with zero action from any attacker: incomplete data is not the
  same fact as benign data, and it now stays in the triage queue instead of being silently
  deprioritized. 26 lines in `services/classifier.py`, 55/4 in `services/orchestrator.py`,
  76/3 in `shared/utils.py`; 1120 lines of regression tests across
  `tests/test_classifier.py`, `tests/test_orchestrator.py`, `tests/test_utils.py`. Full
  suite: 360 passed, 1 skipped, 0 failed; ruff 0 violations.

  **Known gaps, declared rather than hidden** (same policy as `CLS-01j`/`CLS-01w`), tracked
  separately unless noted: `orchestrator.py:452` still emits `needs_review` hardcoded for the
  dnstwist discovery path, bypassing the classifier entirely — untouched by this change;
  `_persist_intel` still calls `_module_failed` without the `requested` filter introduced
  here, so a section disabled by operator flags, e.g. `include_whois=False`, can freeze a
  stale snapshot indefinitely instead of being treated as "not requested"; `CODE-23`
  (fixed in its own entry above; measured on a set of real snapshots: the guard is evaluated
  *after* the positive classification rules, which return first — **33% of the snapshots
  escape the downgrade** because a positive rule fires before the guard is ever reached,
  `cert`/crt.sh is the failing section in **98% of the guard-eligible cases**, and **about
  one domain in ten classified as a whitelist candidate would change outcome** if the guard
  were moved ahead of the rules — not fixed in this change: re-ordering changes classification for
  every existing case and needs a before/after measurement of its own); `dns` stays
  outside `_build_collection_status`'s four sections — a total DNS service outage is still
  indistinguishable from "no records found". **`CODE-26` — accepted risk, explicitly**: with
  `insufficient_data` now `MEDIUM`, a case an analyst closed at `severity_at_detection=LOW`
  (`parking`, `inactive`, `benign`, `legitimate`, `legitimate_probable`, `likely_third_party`,
  `for_sale`) can be auto-reopened by a bare collection failure on the next rescan
  (`case_manager.py:575-611`, `SEVERITY_RANK` comparison) — noise from an infrastructure
  hiccup, not new evidence. The user accepted it explicitly on the condition that `CODE-26`
  is fixed before this change is released (it is, in its own entry above).
- **`_check_vt` in the reputation service (`:8005`) unconditionally slept 16s on every
  VirusTotal lookup, even on a 404 or an HTTP error with nothing to cache (`PERF-01`).** The
  rate limit was enforced with a fixed `time.sleep(16)` placed *after* the response had already
  come back, inside the response path itself — the same 16s penalty on an instant 404 as on a
  genuine successful lookup, serialized on every domain in the pipeline. Four gate rounds were
  needed to land the replacement: a shared token-bucket limiter (same principle as the WHOIS
  gate, `whois_intel.py:65-71`) that waits *before* the call instead of sleeping unconditionally
  after it, counting every real call — success, 404, or error — against the same sliding window
  so the VT quota (free tier: 4 req/60s) is respected regardless of outcome. Rounds 1-3 each
  patched one malformed value of the new `VT_RATE_LIMIT`/`VT_RATE_WINDOW` env vars (a literal
  `0`, then `<=0`, then a small positive/`nan`/`inf`) instead of validating the whole class —
  and rounds 2-3 exposed a blast radius reaching well past this one service: `unified.py:23`
  imports `services.reputation` with no `try`/`except`, so a single malformed value (e.g.
  `VT_RATE_LIMIT="3.5"`) raised an unhandled `ValueError` at import time and took down the
  *entire* unified platform on a typo in one env var for one service, not just the VT lookup.
  **User decision (2026-07-31), a customer-facing behavior choice, not an internal detail**:
  instead of failing fast, a malformed `VT_RATE_LIMIT`/`VT_RATE_WINDOW` now falls back to the
  same known-safe defaults already exhaustively verified (`4`, `60.0` — tested
  under burst load, 8/200-thread concurrency, and aggregate-quota checks) rather than disabling
  rate limiting outright; the fallback is logged (`logger.warning`, variable name + sanitized
  malformed value + default applied) so the anomaly is observable and consumable by future
  `CODE-14` work, not silent. Validation is now a *class* check
  (`math.isfinite(value) and value > 0`) applied at import time, replacing the value-by-value
  patches of rounds 1-3. 12 regression tests (`tests/test_reputation.py`, new). Full suite: 330
  passed, 0 failed; ruff 0/0. Regression counterproof: reverting only the fix in
  `services/reputation.py` (`git stash`) reproduces all 12 failures again.
- **Tracking-pixel detection still ran on truncating regex after the iframe/form sections had
  moved to a browser-accurate tokenizer (`CLS-01i`).** `<img[^>]*>` truncated at the first
  literal `>`, including one inside a quoted attribute value, producing a total false negative
  on a real 1×1 pixel; a duplicate `width` attribute was matched wherever it appeared in the
  tag instead of the browser's first-wins value, and `src\s*=` matched `data-src=` before the
  real `src`, reporting a decoy endpoint to the analyst. Migrated to the `CLS-01g` tokenizer.
  `src`/`action` across all three sections (tracking pixels, invisible iframes, hidden forms)
  are now capped at 300 characters and stripped of CR/LF and control characters before
  persisting to the snapshot (`CLS-01s`) — both were previously unbounded, attacker-controlled
  fields. 12 regression tests.
- **A never-closed `<iframe>` silently swallowed every tag that followed it, and a
  regularly-closed one could still be evaded — both from the same wrong model of HTML5
  `RAWTEXT` (`CLS-01j`, `CLS-01q`).** `<iframe>` content is `RAWTEXT`: real browsers close it
  at the first literal `</iframe`, with no nesting. Three fix attempts were rejected across
  gate rounds before converging: unconditionally suppressing `RAWTEXT` correctly stopped the
  swallowing but then scanned the fallback text of a *legitimately closed* iframe as if it were
  page markup (a 640×480 real iframe with an unrelated `<form style="display:none">` in its
  fallback text raised `hidden_forms`, risk 40, CRITICAL); a LIFO stack of open containers fixed
  that but modeled nesting that doesn't exist in `RAWTEXT` and broke on any unbalanced
  open/close count (e.g. 2 opens / 1 close), which a real browser resolves unambiguously but the
  stack did not. The final design tracks a single active-opaque-region index — at most one
  region open at a time, matching the real, non-nesting semantics — marked opaque only when the
  container closes for real; a never-closed iframe leaves nothing marked, so content after it
  keeps being scanned normally. Also closes the quadratic blow-up the LIFO version introduced
  (`CLS-01v`): retroactive marking on every close was O(k) per close, O(n²) on well-formed
  nesting (20,000 nested iframes: 6.86s; 80,000: did not finish in 120s); the single-index
  design is O(n) by construction (80,000 in 2.33s). **Known, declared detection gap**: suspicious
  fallback content inside a *regularly closed* iframe (e.g. a fake nested `<iframe>`/`<img>`
  pointing at an external host) now produces no finding at all — not a regression against
  the released code (the heuristic explored for it was never shipped), but flagged HIGH priority by
  both independent reviewers for a follow-up (`CLS-01w`: total gap + public source code + low
  reproduction cost). 17 regression tests across the two IDs plus the perf test.
- **`width`/`height` dimension parsing used the wrong HTML5 algorithm, both under- and
  over-detecting (`CLS-01r`).** The pixel-size heuristic truncated to the leading digit prefix
  ("rules for parsing non-negative integers"), when `width`/`height` follow the "rules for
  parsing dimension values" instead: a decimal rounds up on its first fractional digit
  (`"0.5"` → a real, visible 1px; `"1.5"` → a real 2px) and a value can resolve to a pixel or a
  percentage. `width="0.5"` on an iframe was reported as a real 0×0 iframe (same `technique` as
  a literal `"0"`) though it is a genuine 1px element; `width="1.5"` on an `<img>` was flagged
  as a 1×1 tracking pixel though it renders at 2px. Rewritten as `_parse_dimension`
  implementing the real algorithm; the `technique` field now distinguishes literal / rounded /
  percentage so the reported reason never implies a false absolute-pixel match. Percentages
  that resolve to 0/1 (e.g. `"1%"`) are still flagged as suspicious by deliberate product
  choice, not spec conformance — documented explicitly in code and in the finding, per an
  explicit non-negotiable constraint from this decision. 9 regression tests.
- **A crafted `width`/`height` value could permanently disable the whole detector for its own
  domain (`CLS-01t`, introduced by the `CLS-01r` rewrite above, closed in the same cycle before
  ever shipping).** The new dimension parser called `int()` on the matched digit prefix with no
  length cap; past 4,300 digits, CPython's own DoS guard (`sys.set_int_max_str_digits`) raises
  an uncaught `ValueError` that propagated to the `/http` route as a 500 — reliably and
  reproducibly, for any domain that served one oversized attribute value. Fixed with a length
  guard evaluated *before* calling `int()` (not a `try`/`except`, which would have masked
  rather than prevented the failure); the guard correctly no-ops when
  `sys.get_int_max_str_digits()` reports `0` (CPython's own sentinel for "no limit"). 5
  regression tests, including the exact CPython boundary (4,300 vs. 4,301 digits) and a
  subprocess-level check for the `PYTHONINTMAXSTRDIGITS=0` case.
- **Note on the four fixes above (`CLS-01i`/`CLS-01j`/`CLS-01q`/`CLS-01r`): they change which
  patterns produce a finding, not just the schema.** No persisted data format changes, but
  intel snapshots collected under the previous behavior will be re-evaluated differently — and
  silently — the next time each domain is scanned. This is the same category of effect already
  accepted for the `CLS-01g`/`CLS-01h` migrations below; flagged here again because the surface
  is larger (three sections instead of one).
- **Invisible-iframe detector missed self-closing iframes entirely, then went through four
  regex patches that each fixed one malformed-markup shape while breaking another
  (`CLS-01g`).** The original `re.finditer(r'<iframe[^>]*>(.*?)</iframe>', ...)` requires a
  literal `</iframe>` closing tag, so a self-closing `<iframe ... />` — a form used by real
  phishing kits — was a total false negative on a security-relevant signal. Successive
  regex-only rounds traded one failure mode for another: an ordered `|` alternation truncated
  tags whose attribute value happened to contain the literal substring `/>`; a possessive
  per-attribute grammar then failed the *entire* tag match (not just the offending attribute)
  on an unquoted value containing `=` in a querystring, on an orphan `=`, and on an apostrophe
  inside an unquoted value — all markup real browsers accept without complaint. Replaced the
  whole regex chain with a stdlib `html.parser.HTMLParser` tokenizer (`_TagCollector`/
  `_collect_tags`) that hands back attributes already structured the way a browser parses
  them, and fixed a latent duplicate-attribute bug surfaced by the rewrite: a repeated
  attribute (`width="0" width="400"`) now keeps the *first* value per HTML5/browser semantics
  instead of the last, closing an evasion where the reported `src` could be an attacker's
  decoy instead of the real C2 endpoint. 11 regression tests. The "unclosed iframe" heuristic
  explored mid-series as a mitigation for a `RAWTEXT`-swallowing edge case did not converge
  after three verification rounds and was scorporated out; it is tracked separately as
  `CLS-01j` and is not part of this fix.
- **Hidden-form detector missed self-closing forms entirely — the same structural defect
  fixed for iframes by `CLS-01g` (`CLS-01h`).** All four `hidden_form_patterns` regexes ended
  in a literal `</form>`, so an XHTML-style self-closing `<form ... />` never matched,
  whichever hiding technique it carried (`display:none`, `visibility:hidden`, `opacity:0`,
  `class` containing `hidden`): a total false negative on a credential-harvesting signal.
  Migrated the section to the `CLS-01g` tokenizer (`_collect_tags`) — hiding is a fact of the
  opening tag alone, so requiring the closing tag was never necessary to begin with.
  Collateral gains from retiring the regex chain: a form matching several hiding techniques
  now yields one finding instead of one per pattern; the reported `action` IOC is the full
  attribute value instead of a fragment truncated at the first space or quote; duplicate
  attributes follow the tokenizer's first-wins browser semantics. The security review also
  measured the retired patterns' quadratic cost on adversarial input: a crafted ~2 MB page
  spent ~481 s in this section — detecting nothing — versus ~0.8 s after the migration.
  7 regression tests, plus a green control proving the false negative depended solely on the
  self-closing form of the tag, not on the attributes used.
- **`GET /events` deserialized the entire event history on every call, regardless of how many
  events were requested (`CODE-07`).** `soc_events.ndjson` is append-only and never truncated;
  with `last=5` on a 500-line file, `get_events` still ran `json.loads` on all 500 lines to
  return 5. When `client` is not set and `last` is an explicit positive integer, a single
  sequential read now keeps only the last `last` raw lines in a fixed-size queue and
  deserializes only those — O(last) instead of O(N) `json.loads` calls; `total` stays O(N) but
  no longer deserializes. The `client`-filtered path is unchanged: matches can be concentrated
  in old lines, and a tail-window-then-filter approach would silently miss them — guarded by a
  dedicated regression test. A regression surfaced and fixed in the same round: `deque(maxlen=last)`
  converts `last` to a C `Py_ssize_t`, and a syntactically valid `last` beyond `sys.maxsize`
  (fully attacker-controlled on this unauthenticated route) raised an uncaught `OverflowError`
  → 500; the fast path is now bounded to `0 < last <= sys.maxsize`, falling back to the
  pre-existing unbounded list slice above that threshold, which reproduces the pre-fix 200
  response exactly. Measured on a realistic file (1,759 lines, 689 KB): fast path ~1.2 ms,
  fallback path ~10-24 ms — the fallback path is pre-existing code, not a regression.
  **Known, declared inconsistency, not fixed here**: `total` differs between the two paths on
  corrupted NDJSON lines (the fast path counts every non-empty raw line, the filtered path
  counts only lines that parse) — the root cause is `publish()` appending without `fsync`,
  tracked separately together with log rotation. 8 collected tests (deserialization cost,
  old-match correctness, the `OverflowError` regression and its negative controls).
- **Certificate Transparency lookups (`/cert`) repeated the same crt.sh query for the same
  domain within milliseconds of each other, against a source failing on the large majority of
  domains (`COL-04`).** `services/cert_intel.py` had no cache: every call queried crt.sh fresh,
  adding load to an already-unstable external service (observed HTTP 502 on 76.4% of one
  tenant's domains and 95.0% of another's) with no benefit on repeated lookups within the same
  pipeline run. Added an in-process cache with a TTL (`CT_CACHE_TTL`, default 300s) and a
  size-bounded FIFO eviction (`CT_CACHE_MAX_SIZE`, default 500), guarded by an explicit lock to
  avoid the unguarded-eviction race already on record for the WHOIS cache (tracked separately). Only
  successful results are cached: caching a 502 with the same TTL as a valid result would turn a
  transient outage into a 5-minute enrichment gap even after crt.sh recovered — exactly the
  scenario of an operator re-triggering after seeing `cert.total = 0` and staying stuck.
  `tls_live` is deliberately excluded: it reflects the site's live TLS state at request time,
  not a historical CT fact. **Honestly scoped benefit**: the pipeline calls `/cert` once per
  domain per run, so for the 76-95% of domains that were erroring the cache saves zero requests
  on the dominant path; the real value is on the success path and on manual re-triggers within
  the TTL window. 2 regression tests.
- **`lstrip("www.")` truncated every domain starting with `w`.** `str.lstrip` removes any
  leading character belonging to the set `{w, .}`, not the `"www."` prefix: `wind.it` became
  `ind.it`, `wallmart.com` became `allmart.com`. The comparison between the site's own domain
  and the hosts of its resources was wrong in both directions — a subdomain of the site was
  counted as third-party (`static.wind.it` on `wind.it`), and a genuinely unrelated third party
  colliding with the truncated form was silently excluded. Replaced by an anchored
  `_strip_www()` helper used at both call sites; the helper also drops the port, since a
  resource host extracted from HTML can carry one (`static.wind.it:8443`) while the site domain
  never does. 5 regression tests.
- **Hidden-element detector: two unanchored regexes produced systematic false positives.**
  `[01]` and `1` matched the *first digit* of any number, and every following group was
  optional, so the match had no terminator. A SoundCloud iframe with `height="450" width="100%"`
  was classified as an invisible iframe (match on the `1` of `100%`), and a `146×172` site logo
  was classified as a tracking pixel (match on the leading `1` of both dimensions). Measured on
  client data, this detector produced two thirds of the `needs_review` cases that required manual
  inspection on one tenant — all of them benign. Anchored with a lookahead; genuine 0×0 GTM
  noscript iframes and real 1×1 pixels are still detected. 5 regression tests.
- **The CI never ran.** `.github/workflows/ci.yml` triggered on `main`, but this repository's
  branch is `master`: no push has ever executed the `lint`, `test` or `docker` jobs, on any of
  the 8 published releases. It explains how 207 lint violations and a test suite that could not
  even be collected (missing `httpx`) shipped unnoticed.

- **A failed enrichment module no longer poisons the baseline, in either direction.** The
  orchestrator persisted every section of the intelligence snapshot even when its module had
  failed — a transport error yields `None`, an unreachable external source yields the empty
  shape with `error` set. The cycle OK → FAILED (baseline zeroed) → OK then reported a delta
  equal to the domain's entire history rather than the real change: on one tenant this produced
  "new certificates" alerts whose count matched the full Certificate Transparency history,
  28.4% of the alert volume, precision 0.00. A failed section now keeps the previous
  observation instead of overwriting it. The mirror case is covered too: a section absent or
  `null` in the baseline is *the absence of a baseline*, not a baseline of zero, so the first
  successful observation populates it silently instead of reporting the whole history as new.
- **DNS report fields read "yes" once a scan had run, regardless of what it found.** The
  client HTML report used `dns.A ? "yes" : "no"` and the equivalent for `MX`: a JavaScript
  array is truthy even when empty, so the field reported "the DNS collection executed", not
  "the record exists". On real data from two clients, domains with **zero** MX records were
  rendered with the red `MX: yes` flag — the near-identical `A` and `MX` counts were the
  fingerprint. Now checks `.length`, not existence. 1
  regression test (a static source assertion — this project has no JS test runtime, so the
  fix is verified on the text of `buildHtmlReport()` rather than by executing it).
- **Client HTML report projected 4 fields out of roughly 40 collected per domain.** The
  document handed to clients showed only A / MX / Website / Certificates, discarding
  registrar, WHOIS dates, page title, content size, reputation score and per-module
  collection status. `Certificates: 0` was indistinguishable between "no certificates" and
  "crt.sh failed"; a new `Module status` row now shows `ok` / `errore` / `non raccolto` per
  section instead of a report that silently omits the caveat. 1 regression test.
- **The client's own legitimate domain became a typosquatting case on itself.** In a real
  feed, more than half of the entries were the client's own domain — standard onboarding, not a
  misconfiguration — and the case-ingest step opened a case for it exactly like any
  lookalike candidate, so every tenant received an alert on its own primary asset. Excluded
  from case ingest only: monitoring and compromise detection on the legitimate domain are
  unchanged. 2 regression tests.
- **`/cases` total count ignored the active filters.** The count query was `SELECT COUNT(*)
  FROM cases` with no `WHERE`, while the page query applied the status/client/severity
  filters, so pagination showed the unfiltered global total next to a filtered page.
  Extracted a single predicate builder shared by both queries so they cannot diverge again.
  2 regression tests.
- **Case severity was never reconciled at closure.** On real data, every case closed as
  false-positive or benign kept its original MEDIUM severity, all but one demonstrably wrong — a resolved
  non-issue looked identical to an open one in every severity-based view or filter. Closing a
  case as `closed_fp`/`closed_benign` now downgrades `severity` to `INFO` and preserves the
  value observed at detection in a new `severity_at_detection` column, which per-detector
  precision reporting depends on. `closed_tp` is untouched: a confirmed true positive's
  severity is the incident, not a downgrade candidate. Idempotent migration retrofits
  pre-existing closed rows so their historical severity isn't lost. 8 regression tests.
- **CRITICAL alerts were 100% false positives on one tenant.** All the CRITICAL alerts
  observed there (28.4% of that tenant's alert volume) were routine Domain Validation
  certificate issuance on unrelated third-party domains — free, automated, renewed every
  60-90 days across most of the web, not malicious activity. CRITICAL is now reserved for
  observed malicious activity (credential harvesting, injected content, reputation-source
  confirmation); certificate and status-change events downgrade to MEDIUM/HIGH, and a new
  `INFO` level absorbs routine maintenance events (SOA/header/WHOIS-renewal changes) that
  don't belong in a triage queue. Severity ordering, previously redeclared in four separate
  places, is now a single `shared.constants.SEVERITY_ORDER`. 5 regression tests.

### Changed
- **Lint gate made reproducible.** `ruff` was installed unpinned in CI, so its default rule set
  changed with every upstream release and the gate passed or failed depending on the day.
  `pyproject.toml` now fixes the selection to `["E4", "E7", "E9", "F", "B"]`, chosen for signal
  over style: `B008` is ignored (FastAPI's whole API is built on call-in-default — 44 false
  positives on idiomatic code), as are `E401/E701/E702` (deliberate and consistent across the
  services) and `E402` (conditional imports are intentional). `B` stays on and pays for itself:
  `B005` had already found the `lstrip` bug above before any human review. All 44 violations
  resolved — 207 → 0.
- **Development dependencies pinned and documented.** `requirements-dev.txt` adds
  `pytest==9.1.1`, `httpx==0.28.1`, `ruff==0.16.0`. `httpx` is required by
  `fastapi.testclient.TestClient`: without it the suite failed at collection, and CI only got it
  by side effect.

### Security
- **Client whitelist data can no longer be committed.** `docker-compose.yml` mounts
  `./config/whitelists` read-write and the feed-manager writes per-client whitelists there, so
  real client data accumulated inside the source tree with no `.gitignore` rule covering it — on
  a repository that is public. Verified that no leak ever occurred (`git log -- 'config/whitelists/*'`
  shows only the initial commit with `example.txt`). The rule carries no exception, not even for
  `example.txt`: `_safe_client_name` accepts the client name `example`, so an exception on that
  path would have been a hole. `example.txt` stays versioned because it is already tracked.
- **`docker-compose.prod.yml` published every service port, contradicting the documented
  security model.** The README describes the orchestrator and intelligence services as
  staying on an internal Docker network in production, reachable only through `dashboard`
  and `case-manager` — but the production compose file published all of `8000-8013` on the
  host. Anyone following the README believed they were protected while the entire
  unauthenticated engine (`/trigger`, `/intel`, `/progress`, `/events`, `/feed/*`) was
  reachable. Internal services now use `expose:`; only `case-manager` and `dashboard` still
  publish a port.
- **The unified-mode compose file exposed the unauthenticated zone on the network.** Its
  port was published on every interface, and with `FEED_REQUIRE_AUTH=false` anyone reaching
  it could read `/events` and `/intel` for every client, trigger scans against
  VirusTotal/OTX/SecurityTrails quotas, and write or delete feed entries — without
  credentials. Default bind is now loopback-only (`127.0.0.1`), configurable via `BIND_ADDR`
  in `.env` for deployments that put a reverse proxy in front of the authenticated paths only.

## [4.21.0] - 2026-07-19

### Improved
- **Domain age now modulates threat severity instead of acting only as a fallback.**
  Measured on three real client datasets, the HIGH bucket was dominated by decades-old
  legitimate businesses: every HIGH on one client was a domain registered 2000-2008, and
  80% on another. The cause was rule ordering: weak signals fired and returned HIGH
  before the age rule was ever reached. Weak signals (`hidden_elements`, `mx_only_no_web`,
  `privacy_mx_provider`, `forwarding_mx`) now downgrade to `needs_review`/MEDIUM on
  domains older than `AGE_THIRD_PARTY_DAYS` (540), and alarm only on recent registrations.
  Result on the same data: HIGH fell by 100% and 80% on the first two clients and did not
  change on the third, with every known threat still surfacing as HIGH and no new false negatives.
- **WHOIS `updated_date` no longer escalates severity.** The re-registration heuristic
  treated any recently-updated old domain as a possible drop-catch, but that field also
  changes on routine annual renewal, so nearly every actively maintained legacy domain
  matched. It now only prevents automatic clearing to LOW (case stays `needs_review`),
  and the rationale says explicitly that a renewal is the likelier explanation.
- **Recent inert look-alikes get an explicit rule** (`recent_registration_inactive`)
  instead of the generic `no_matching_rule`, stating that the domain was registered in
  the hostile-registration window and is currently dormant, so it should be monitored for
  activation rather than archived.
- `AGE_THIRD_PARTY_DAYS` moved to shared constants; age is now computed once per
  classification instead of three times. 6 regression tests.

## [4.20.1] - 2026-07-18

### Security / Fixed
- **Bug hunt + security audit on the severity/proposal code (v4.19.0–4.20.0).**
  - **Unbounded input fields**: no request field had a length limit, so an authenticated
    caller (or the orchestrator with manipulated data) could write multi-megabyte values
    into the DB via `rationale`, `reason`, `note`, `domain`, `client`, `username`
    (storage abuse / DoS). All input models now enforce `max_length`; oversized payloads
    get 422. Verified normal inputs still pass.
  - **Orphaned proposal**: if a pending classifier proposal existed and the analyst then
    set the severity by hand, the stale proposal kept showing in the UI. Setting or
    releasing a manual severity now clears any pending proposal.
  - Confirmed safe: proposal reason is HTML-escaped in the UI (no stored XSS);
    `sanitize_log_input` strips newlines (no audit-log injection); migrations are
    idempotent across repeated restarts (no duplicate columns); domain/client fields are
    parameterized in SQL (injection attempt stored harmlessly, table intact).
  - 6 regression tests.

## [4.20.0] - 2026-07-18

### Added
- **Severity proposals: the classifier can ask, instead of being ignored.** When a re-scan
  rates a case HIGHER than the severity an analyst set by hand, the finding is no longer
  silently discarded (nor does it overwrite the analyst). A proposal is filed on the case
  and must be explicitly approved or rejected:
  - `POST /cases/{id}/severity/proposal` with `{"action": "approve" | "reject"}`.
    Approving adopts the proposed severity and keeps it locked (it is now an analyst
    decision); rejecting keeps the current severity. Either way the proposal is cleared.
  - Dashboard: an amber **!** marker appears next to the severity in the case list, and
    the case detail shows a banner explaining the disagreement with Accept / Keep buttons.
  - Both the proposal and its resolution are recorded in the case audit trail.
- Schema migration (idempotent) adds `cases.pending_severity`, `pending_severity_reason`,
  `pending_severity_at`. Verified against both a pre-4.19 database and a 4.19 database:
  columns added, existing cases preserved.
- 7 regression tests.

### Rationale
Keeping a manual severity is right, but a classifier that later sees a domain arm itself
should not lose that signal in the audit log. The proposal makes the disagreement visible
and forces an explicit decision, without ever overriding the analyst automatically.

## [4.19.0] - 2026-07-18

### Added
- **Manual severity override.** `PATCH /cases/{id}/severity` lets an analyst set a case
  severity by hand when the automatic classification gets it wrong. A manually set
  severity is *locked*: subsequent scans refresh classification, confidence and rationale
  but leave the severity untouched, so analyst judgement is never silently reverted.
  Send `severity: null` to release the override and follow automatic classification again.
- Dashboard: severity selector with "Set severity" and "Back to auto" in the case actions,
  plus a marker in the case list showing which severities were set by hand.
- The override is recorded in the case audit trail, with the optional reason.
- Schema migration (idempotent) adds `cases.severity_locked`; existing cases default to
  automatic. Verified on a pre-migration database: column added, data preserved.
- 5 regression tests.

### Notes
- A locked severity is also preserved when an escalation reopens a closed case: the case
  returns to the queue (that is the point) but the analyst's rating stands, and the audit
  records what the classifier saw.

## [4.18.5] - 2026-07-18

### Changed
- **Closed cases now reopen on severity escalation, not only on CRITICAL.** Previously a
  closed case came back into the queue only if a re-scan reported CRITICAL, a level the
  classifier never emits: in practice a domain closed as benign that later armed itself
  (e.g. re-classified `suspicious`/HIGH) stayed closed and silently out of sight. Reopening
  is now relative: a case reopens when the new severity ranks higher than the one recorded,
  and the audit trail records the transition (`severity escalated MEDIUM -> HIGH`).
- Re-scans at equal or lower severity still leave closed cases untouched, so routine
  scanning never undoes analyst triage. When a case has no recorded severity, MEDIUM is
  assumed as the baseline so that LOW findings cannot reopen it.
- Ingest response now returns `escalated_from` / `escalated_to` on reopen.
- 4 regression tests. Verified on one client's dataset: none of its closed cases would
  reopen on the next scan.

## [4.18.4] - 2026-07-18

### Fixed
- **dnstwist variants were never classified: every variant case was hardcoded to
  `needs_review` / MEDIUM.** The orchestrator built variant events with a fixed
  `auto_classification: "needs_review"` placeholder from discovery and never called the
  classifier for them. The classifier was only consulted for monitored (target) domains,
  so *all* classifier improvements (including the v4.18.0 domain-age rule) had no effect
  on variant cases. Variants with collected intel are now sent to `/classify/variant` and
  the real classification is used.
- **Severity map was missing the classifier's newer categories** (`likely_third_party`,
  `legitimate_probable`, `for_sale`), which silently fell back to MEDIUM. Now mapped to LOW.

### Changed
- Dashboard: the "Collect full intel on variants" option now states that it is required
  for auto-classification (without WHOIS the age rule cannot run and variants stay
  `needs_review`).
- 2 regression tests.

### Impact
On one client's dataset, variant classification goes from 100% `needs_review`/MEDIUM to
8% HIGH (the confirmed threats), 21% MEDIUM, 54% LOW.

## [4.18.3] - 2026-07-08

### Fixed
- **Pipeline lock could get stuck, blocking all scans with HTTP 409.** If a pipeline
  died in a way that skipped cleanup (OOM, SIGKILL, container crash), the in-memory
  `_running` flag stayed True and every new scan was rejected with 409 until the service
  was restarted by hand. Found in production when onboarding a new client.

### Added
- **Heartbeat-based stale detection.** Pipeline progress now bumps a heartbeat; if it
  stops advancing for `HEARTBEAT_STALE_SEC` (default 600s), the next `/trigger`
  auto-recovers instead of blocking indefinitely. Far quicker than the existing 2h
  absolute-duration reset.
- **`POST /trigger/reset`** endpoint: operator escape hatch to release the pipeline lock
  immediately without restarting the service. Follows the orchestrator network-isolation
  model (no app-level auth; internal-only).
- `/trigger` 409 responses now include `seconds_since_heartbeat` for diagnosis.
- 3 regression tests.

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
  - 5 security regression tests. The real client datasets tested classify identically (no behavior change).

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
  - 7 regression tests. Verified the real client datasets tested classify identically to
    v4.18.0 (no behavior change, only crash/robustness fixes).

## [4.18.0] - 2026-07-07

### Improved
- **Classifier now uses domain registration age (the strongest typosquatting signal).**
  Previously the classifier ignored WHOIS creation date and dropped most variants into
  `needs_review`, leaving ~80% of triage to the analyst. It now auto-classifies a domain
  that predates the hostile-registration window (>18 months old) and shows no threat
  signals as `likely_third_party` (LOW), clearing it from the manual queue. Measured on
  a set of real client datasets: `needs_review` dropped by 87%, with zero false
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
  Discovered while triaging real client data — a client's legitimate domain (a
  WordPress app with a login area) and dozens of proper-name domains
  were flagged as "compromise / credential kit". Three root causes fixed:
  1. **Obfuscated-JS detection**: unicode/hex escape sequences ALONE (e.g. wp-emoji's
     many \uXXXX) no longer mark a script as obfuscated. Requires a genuine signal
     (eval/atob/fromCharCode/document.write/unescape/charcode_array) or encoding +
     such a signal.
  2. **External-resource counting**: resources hosted on the page's OWN domain or its
     subdomains (e.g. client.example/wp-content/…, download.client.example/…) are no longer
     counted as external/third-party. Known CDNs (WordPress.com, fonts, social) also
     excluded. `detect_hidden_elements(html, self_domain=…)` now takes the page domain.
  3. **credential_form_detected**: a login area is normal on the client's legitimate
     domain and on countless third-party sites — it no longer alerts on the legitimate
     domain, and on variants only fires for credential patterns that are NEW vs. the
     baseline (a form appearing where there was none), not for any "login" string.
  - Verified on real data: the client's legitimate domain now scores risk 0 (was CRITICAL); a genuine
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
  A client with several targets that share the same legitimate (e.g. 3 targets that
  all map to client.example) triggered the full dnstwist discovery + variant-intel
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
  real client domain — the diffing path is only exercised when a prior snapshot exists.
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
  only the dashboard); they must not be publicly reachable. Documented in the README
  security section.

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
