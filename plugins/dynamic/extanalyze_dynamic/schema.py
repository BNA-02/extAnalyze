"""Validation of the sandbox driver's output. The driver runs next to untrusted code, so its
output is treated as untrusted: only known keys, bounded sizes, expected types."""

from __future__ import annotations

MAX_OUTPUT_BYTES = 2 * 1024 * 1024
_MAX_ITEMS = 500
_CANARIES = {"email", "password", "card", "cookie", "storage", "search"}
_SOURCES = {"page", "service_worker", "background_page"}


class InvalidDriverOutput(ValueError):
    pass


def _s(value, limit: int = 300) -> str:
    return str(value)[:limit] if isinstance(value, str | int | float) else ""


def _list(value) -> list:
    return value[:_MAX_ITEMS] if isinstance(value, list) else []


def validate(raw: object) -> dict:
    """Return a sanitized copy of the driver output or raise InvalidDriverOutput."""
    if not isinstance(raw, dict) or raw.get("schema") != 1:
        raise InvalidDriverOutput("unexpected driver output")
    if isinstance(raw.get("error"), str):
        raise InvalidDriverOutput(f"sandbox driver error: {_s(raw['error'], 500)}")

    requests = []
    for r in _list(raw.get("requests")):
        if not isinstance(r, dict):
            continue
        requests.append(
            {
                "url": _s(r.get("url")),
                "method": _s(r.get("method"), 10),
                "resource_type": _s(r.get("resource_type"), 30),
                "source": r.get("source") if r.get("source") in _SOURCES else "page",
                "body_bytes": r.get("body_bytes") if isinstance(r.get("body_bytes"), int) else 0,
                "canaries": [c for c in _list(r.get("canaries")) if c in _CANARIES],
            }
        )
    hits = []
    for h in _list(raw.get("canary_hits")):
        if isinstance(h, dict) and h.get("canary") in _CANARIES:
            hits.append(
                {
                    "canary": h["canary"],
                    "encoding": _s(h.get("encoding"), 20),
                    "url": _s(h.get("url")),
                    "method": _s(h.get("method"), 10),
                }
            )
    return {
        "schema": 1,
        "browser": _s(raw.get("browser"), 60) or None,
        "extension_id": _s(raw.get("extension_id"), 40) or None,
        "background_observed": bool(raw.get("background_observed")),
        "pages_visited": [_s(p, 100) for p in _list(raw.get("pages_visited"))],
        "requests": requests,
        "external_hosts": [_s(h, 253) for h in _list(raw.get("external_hosts"))],
        "canary_hits": hits,
        "console_errors": [_s(e, 200) for e in _list(raw.get("console_errors"))[:20]],
        "notes": [_s(n, 300) for n in _list(raw.get("notes"))[:50]],
        "duration_s": raw.get("duration_s")
        if isinstance(raw.get("duration_s"), int | float)
        else 0,
    }
