# Contributing to DomainSentry

Thanks for considering contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/mattiapapini-spec/domainsentry.git
cd domainsentry
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt   # pinned pytest, httpx, ruff
```

Run locally:
```bash
SERVICE_HOST=127.0.0.1 PYTHONPATH=. python run_service.py unified     # all services on port 8000
SERVICE_HOST=127.0.0.1 PYTHONPATH=. python run_service.py dns-intel   # single service on port 8001
```

## Running Tests

```bash
PATH=/path/to/node/bin:$PATH python3 tests/run_parallel.py -n 4   # parallel driver
PYTHONPATH=. pytest tests/ -q                                    # serial, as in CI
```

The tests never use the network. Node.js is needed for the dashboard rendering tests (they
are skipped without it, and fail with `DOMAINSENTRY_REQUIRE_NODE=1`). See
[README § Tests](README.md#tests) for the fixed `/tmp` paths and how to stop the driver.

## Code Style

- Python 3.12+
- Use `ruff` for linting: `ruff check .`
- Type hints where practical
- Docstrings on public functions and endpoints
- Keep services self-contained — each service file should be understandable in isolation

## Pull Requests

1. Fork the repo and create a feature branch
2. For a bug fix, add a regression test that fails before the fix and passes after it
3. Run the test suite and `ruff check .` (zero violations) before submitting
4. Keep PRs focused — one feature or bugfix per PR, and the smallest diff that does the job
5. Update CHANGELOG.md: what did not work, why, and what changed, with numbers where you measured them
6. Use only `.example` domains and documentation IP ranges (RFC 5737) in tests, fixtures and docs, never real client or third-party data

## Architecture Principles

- **Every service must work standalone.** `curl http://service:port/endpoint` must return valid JSON without any other service running.
- **Graceful degradation.** If a dependency is down, continue without it. Never block the pipeline for an optional component.
- **JSON everywhere.** Every input is JSON, every output is JSON.
- **No invented data.** If a field is unavailable, use `null`. Never infer or fabricate.
- **A failure is not an absence.** A lookup that fails or does not answer must never be read as "no record": mark it as undetermined, or carry the previous observation over with the date it was last seen.
- **Whitelist is sacred.** Automated processes read the whitelist, never write to it.

## Good First Issues

- Add pagination (`offset`/`limit`) to list endpoints
- Improve OpenAPI descriptions and tags on endpoints
- Add startup validation (check dependencies on boot)

## Security

Please do not report security vulnerabilities in public issues: follow [SECURITY.md](SECURITY.md).
