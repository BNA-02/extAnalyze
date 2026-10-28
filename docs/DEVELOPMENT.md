# Development

```bash
# Reproducible, hash-verified install (recommended)
pip install --require-hashes -r requirements-dev.lock
pip install --no-deps -e .

# Lint
ruff check extanalyze/
ruff format extanalyze/

# Tests (unit tests, no network)
pytest tests/ -v

# SAST
bandit -r extanalyze/ -c pyproject.toml

# SCA
pip-audit
```

CI runs on push/PR via two workflows:
- `.github/workflows/ci-dev.yml` - triggers on `develop` (fast feedback, single Python, informational SAST)
- `.github/workflows/ci-main.yml` - triggers on PR to `main` (full matrix, hard SAST gate, build check)

## Branching

All changes go to `develop` first and reach `main` through a pull request. Dependabot opens its PRs against `develop`.

## README table of contents

The table of contents in `README.md` is maintained by hand. Update it when `##` headings change.
