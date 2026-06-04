# Contributing to DomainSentry

Thanks for considering contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/domainsentry.git
cd domainsentry
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pytest ruff
```

Run locally:
```bash
PYTHONPATH=. python run_service.py unified       # all services on port 8000
PYTHONPATH=. python run_service.py dns-intel      # single service on port 8001
```

## Running Tests

```bash
pytest tests/ -v
```

## Code Style

- Python 3.12+
- Use `ruff` for linting: `ruff check .`
- Type hints where practical
- Docstrings on public functions and endpoints
- Keep services self-contained — each service file should be understandable in isolation

## Pull Requests

1. Fork the repo and create a feature branch
2. Add tests for new functionality
3. Run `pytest` and `ruff check .` before submitting
4. Keep PRs focused — one feature or bugfix per PR
5. Update CHANGELOG.md

## Architecture Principles

- **Every service must work standalone.** `curl http://service:port/endpoint` must return valid JSON without any other service running.
- **Graceful degradation.** If a dependency is down, continue without it. Never block the pipeline for an optional component.
- **JSON everywhere.** Every input is JSON, every output is JSON.
- **No invented data.** If a field is unavailable, use `null`. Never infer or fabricate.
- **Whitelist is sacred.** Automated processes read the whitelist, never write to it.

## Good First Issues

- Add tests for `detect_hidden_elements` in `shared/utils.py`
- Add pagination (`offset`/`limit`) to list endpoints
- Add CORS middleware to all services
- Improve OpenAPI descriptions and tags on endpoints
- Add startup validation (check dependencies on boot)

## Security

If you find a security vulnerability, please email directly instead of opening a public issue.
