"""Turn sandbox observations (from the dynamic plugin) into findings.

Runtime-confirmed behaviour is stronger evidence than static indicators, so these findings use
the CR-RT-* ids and are scored outside the static code-review cap (see scoring/aggregator.py).
"""

from __future__ import annotations

from .code_review import CodeFinding, CodeReviewResult, Location, record, sort_findings

_CANARY_LABELS = {
    "email": "typed e-mail address",
    "password": "typed password",
    "card": "typed card number",
    "cookie": "session cookie",
    "storage": "localStorage token",
    "search": "search query",
}
_SCRIPT_TYPES = {"script"}


def apply_dynamic(review: CodeReviewResult, observation: dict) -> None:
    """Attach observations to the review and add CR-RT-* findings."""
    review.dynamic = observation
    findings: dict[str, CodeFinding] = {f.rule_id: f for f in review.findings}

    leaked = sorted({h["canary"] for h in observation["canary_hits"]})
    for hit in observation["canary_hits"]:
        record(
            findings,
            "CR-RT-001",
            rule_id="CR-RT-001",
            name="Sensitive data left the browser (canary exfiltration)",
            category="EXFILTRATION",
            severity="CRITICAL",
            description=(
                "Canary values planted in the test pages appeared in outbound requests: "
                + ", ".join(_CANARY_LABELS.get(c, c) for c in leaked)
                + ". Confirmed by running the extension in the sandbox."
            ),
            count=1,
            location=Location(
                hit["url"], 0, f"{hit['method']} carrying {hit['canary']} ({hit['encoding']})"
            ),
        )

    external = observation["external_hosts"]
    if external and not observation["canary_hits"]:
        record(
            findings,
            "CR-RT-002",
            rule_id="CR-RT-002",
            name="Contacts external hosts during test browsing",
            category="NETWORK",
            severity="MEDIUM",
            description=(
                f"{len(external)} external host(s) contacted with no real user data involved: "
                + ", ".join(external[:8])
            ),
            count=len(external),
            location=None,
        )

    for req in observation["requests"]:
        if req["source"] in ("service_worker", "background_page") and req[
            "resource_type"
        ] in _SCRIPT_TYPES | {"fetch"}:
            if req["url"].split("?")[0].endswith((".js", ".mjs", ".wasm")):
                record(
                    findings,
                    "CR-RT-003",
                    rule_id="CR-RT-003",
                    name="Fetches remote code at runtime",
                    category="DYNAMIC_CODE",
                    severity="HIGH",
                    description="The extension's background worker downloads script/wasm from a remote host.",
                    count=1,
                    location=Location(req["url"], 0, f"{req['method']} {req['resource_type']}"),
                )

    review.findings = sort_findings(findings)
