# Development

```bash
# Reproducible install from uv.lock (hash-verified)
uv sync --extra dev

# Lint
uv run ruff check extanalyze/
uv run ruff format extanalyze/

# Tests (unit tests, no network)
uv run pytest tests/ -v

# SAST
uv run bandit -r extanalyze/ -ll -ii -c pyproject.toml

# SCA
uv export --no-emit-project -o /tmp/audit.txt && uv run pip-audit --requirement /tmp/audit.txt --disable-pip
```

CI runs on push/PR via two workflows:
- `.github/workflows/ci-dev.yml` - triggers on `develop` (fast feedback, single Python, informational SAST)
- `.github/workflows/ci-main.yml` - triggers on PR to `main` (full matrix, hard SAST gate, build check)

## Branching

All changes go to `develop` first and reach `main` through a pull request. Dependabot (uv ecosystem) opens its PRs against `develop` and updates `pyproject.toml` and `uv.lock` together.

## README table of contents

The table of contents in `README.md` is maintained by hand. Update it when `##` headings change.
