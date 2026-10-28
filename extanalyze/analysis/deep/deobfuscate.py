"""
Entropy analysis and static deobfuscation (never executes anything).

Decodes obvious string obfuscation (base64 literals, hex/unicode escapes, fromCharCode
lists) and re-runs the code-review rules on the decoded text, so payloads hidden behind
trivial encoding are still caught. Also flags high-entropy string literals.
"""

from __future__ import annotations

import base64
import binascii
import math
import re

from ..code_review import (
    CodeFinding,
    Location,
    SourceFile,
    _line_of,
    _snippet,
    iter_sources,
    record,
    scan_source,
)

_ENTROPY_THRESHOLD = 4.5
_MAX_DECODED_PER_FILE = 200
_MAX_BLOB_CHARS = 100_000
_MIN_PRINTABLE_RATIO = 0.9

_STRING_LITERAL_RE = re.compile(r"""["']([A-Za-z0-9+/=_\-]{30,500})["']""")
_B64_LITERAL_RE = re.compile(r"""["'`]([A-Za-z0-9+/]{24,}={0,2})["'`]""")
_HEX_ESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_UNI_ESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
_CHARCODE_RE = re.compile(r"String\.fromCharCode\s*\(\s*((?:\d{1,3}\s*,\s*){3,}\d{1,3})\s*\)")
_URL_IN_DECODED_RE = re.compile(r"https?://[A-Za-z0-9.\-]{3,253}")


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((n / total) * math.log2(n / total) for n in freq.values())


def _printable(text: str) -> bool:
    if len(text) < 8:
        return False
    ok = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return ok / len(text) >= _MIN_PRINTABLE_RATIO


def _decode_candidates(text: str):
    """Yield (kind, position, decoded_text) for every decodable obfuscated string."""
    for m in _B64_LITERAL_RE.finditer(text):
        blob = m.group(1)
        if len(blob) > _MAX_BLOB_CHARS:
            continue
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _printable(decoded):
            yield "base64", m.start(), decoded
    for m in _HEX_ESC_RE.finditer(text):
        decoded = re.sub(r"\\x([0-9a-fA-F]{2})", lambda x: chr(int(x.group(1), 16)), m.group(0))
        if _printable(decoded):
            yield "hex escape", m.start(), decoded
    for m in _UNI_ESC_RE.finditer(text):
        decoded = re.sub(r"\\u([0-9a-fA-F]{4})", lambda x: chr(int(x.group(1), 16)), m.group(0))
        if _printable(decoded):
            yield "unicode escape", m.start(), decoded
    for m in _CHARCODE_RE.finditer(text):
        try:
            decoded = "".join(chr(int(n)) for n in m.group(1).split(","))
        except ValueError:
            continue
        if _printable(decoded):
            yield "fromCharCode", m.start(), decoded


def analyze(base, relative_files: list[str], findings: dict[str, CodeFinding]) -> list[str]:
    """Add entropy and deobfuscation findings. Returns domains discovered in decoded strings."""
    hidden_domains: list[str] = []
    for src in iter_sources(base, relative_files):
        if isinstance(src, str) or src.vendor:
            continue
        _entropy(src, findings)
        hidden_domains.extend(_deobfuscate(src, findings))
    return hidden_domains


def _entropy(src: SourceFile, findings: dict[str, CodeFinding]) -> None:
    for m in _STRING_LITERAL_RE.finditer(src.text):
        entropy = shannon_entropy(m.group(1))
        if entropy < _ENTROPY_THRESHOLD:
            continue
        record(
            findings,
            "CR-DEEP-ENT",
            rule_id="CR-DEEP-ENT",
            name="High-entropy string literal",
            category="OBFUSCATION",
            severity="MEDIUM",
            description=(
                f"String literals above {_ENTROPY_THRESHOLD} bits/char Shannon entropy: "
                "likely encoded, encrypted or compressed data."
            ),
            count=1,
            location=Location(
                src.rel, _line_of(src.text, m.start()), _snippet(src.text, m.start())
            ),
        )


def _deobfuscate(src: SourceFile, findings: dict[str, CodeFinding]) -> list[str]:
    domains: list[str] = []
    for n, (kind, pos, decoded) in enumerate(_decode_candidates(src.text)):
        if n >= _MAX_DECODED_PER_FILE:
            break
        label = f"{src.rel} [decoded {kind}]"
        # Re-run the standard rules on the decoded text
        decoded_src = SourceFile(label, decoded, False, False)
        hit_ids, _ = scan_source(decoded_src, findings)
        urls = _URL_IN_DECODED_RE.findall(decoded)
        if urls or hit_ids:
            record(
                findings,
                "CR-DEEP-DEC",
                rule_id="CR-DEEP-DEC",
                name="Obfuscated string decodes to code or a URL",
                category="OBFUSCATION",
                severity="HIGH",
                description=(
                    "A string hidden with simple encoding contains a URL or matches code-review "
                    "rules once decoded (decoded text was re-scanned)."
                ),
                count=1,
                location=Location(src.rel, _line_of(src.text, pos), _snippet(decoded, 0)),
            )
        for u in urls:
            host = u.split("//", 1)[1].lower()
            if "." in host:
                domains.append(host)
    return domains
