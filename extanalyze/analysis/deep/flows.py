"""
AST-based data-flow check (tree-sitter): does sensitive data reach a network call?

Flow-insensitive, name-based taint within a single file:
  sources  cookies, history, storage, clipboard, tabs, document.cookie, password fields
  carriers variables/properties assigned from a source, parameters of callbacks passed to a
           source call (chrome.cookies.getAll({}, cb)), anything derived from those
  sinks    fetch, sendBeacon, XHR/WebSocket .send, $.ajax/$.post, axios.*, `img.src = ...`

This is stronger evidence than the regex "same file" heuristic (the data really reaches the
call), but it is not a full analysis: it ignores scoping and cross-file flows, and cannot
see through obfuscation. The traversal is iterative so hostile deeply nested code cannot
exhaust the Python stack.
"""

from __future__ import annotations

import re

import tree_sitter_javascript as tsj
from tree_sitter import Language, Node, Parser

from ..code_review import CodeFinding, Location, SourceFile, record

MAX_NODES = 400_000
MAX_AST_FILE_BYTES = 1_000_000
_SNIPPET_LEN = 100

_SOURCE_RE = re.compile(
    r"cookies\s*\.\s*(?:getAll|get)\b|document\s*\.\s*cookie|history\s*\.\s*(?:search|getVisits)\b"
    r"|\b(?:local|session)Storage\b|clipboard\s*\.\s*readText|tabs\s*\.\s*query\b"
    r"|type\s*=\s*[\"']?password|\[type=[\"']?password",
    re.I,
)
_SINK_CALLEE_RE = re.compile(
    r"^(?:fetch|(?:window\.|self\.)?fetch|navigator\.sendBeacon|\$\.(?:ajax|post|get)|"
    r"axios(?:\.\w+)?|[\w$.]+\.send)$"
)
_FUNCTION_TYPES = {"arrow_function", "function_expression", "function", "function_declaration"}

_parser: Parser | None = None


def _get_parser() -> Parser:
    global _parser
    if _parser is None:
        _parser = Parser(Language(tsj.language()))
    return _parser


def _text(node: Node, limit: int = 400) -> str:
    return (node.text or b"")[:limit].decode("utf-8", errors="replace")


def _walk(root: Node):
    """Iterative pre-order traversal, capped at MAX_NODES."""
    stack = [root]
    seen = 0
    while stack and seen < MAX_NODES:
        node = stack.pop()
        seen += 1
        yield node
        stack.extend(reversed(node.children))


def _contains_taint(node: Node, tainted: set[str]) -> str | None:
    """Return a label if the subtree reads a tainted name or a source expression."""
    for n in _walk(node):
        if n.type == "identifier" and _text(n, 80) in tainted:
            return _text(n, 80)
        if n.type in ("member_expression", "call_expression", "subscript_expression"):
            t = _text(n, 200)
            if _SOURCE_RE.search(t):
                return _SOURCE_RE.search(t).group(0)  # type: ignore[union-attr]
    return None


def _param_names(fn: Node) -> list[str]:
    names = []
    params = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
    if params is None:
        return names
    if params.type == "identifier":
        return [_text(params, 80)]
    for n in _walk(params):
        if n.type == "identifier":
            names.append(_text(n, 80))
    return names


def find_flows(code: str) -> list[tuple[int, str, str]]:
    """Return (line, sink snippet, source label) for each source-to-sink flow in `code`."""
    tree = _get_parser().parse(code.encode("utf-8", errors="replace"))
    nodes = list(_walk(tree.root_node))

    tainted: set[str] = set()
    assignments: list[tuple[str, Node]] = []

    for n in nodes:
        if n.type == "variable_declarator":
            name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is not None and value is not None and name.type == "identifier":
                assignments.append((_text(name, 80), value))
        elif n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and right is not None:
                base = left
                while base.type in ("member_expression", "subscript_expression"):
                    obj = base.child_by_field_name("object")
                    if obj is None:
                        break
                    base = obj
                if base.type == "identifier":
                    assignments.append((_text(base, 80), right))
        elif n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if fn is not None and _SOURCE_RE.search(_text(fn, 200)):
                args = n.child_by_field_name("arguments")
                for a in args.children if args is not None else []:
                    if a.type in _FUNCTION_TYPES:
                        tainted.update(_param_names(a))

    for _ in range(3):  # propagate through assignments to a small fixpoint
        before = len(tainted)
        for target, value in assignments:
            if target not in tainted and _contains_taint(value, tainted):
                tainted.add(target)
        if len(tainted) == before:
            break

    flows: list[tuple[int, str, str]] = []
    for n in nodes:
        sink = None
        data: list[Node] = []
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if fn is not None and _SINK_CALLEE_RE.match(re.sub(r"\s+", "", _text(fn, 120))):
                sink = n
                args = n.child_by_field_name("arguments")
                data = [c for c in (args.children if args is not None else []) if c.is_named]
        elif n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and right is not None and _text(left, 120).endswith(".src"):
                sink, data = n, [right]
        if sink is None:
            continue
        for d in data:
            label = _contains_taint(d, tainted)
            if label:
                snippet = re.sub(r"[\x00-\x1f\x7f]", " ", _text(sink, _SNIPPET_LEN)).strip()
                flows.append((sink.start_point[0] + 1, snippet, label))
                break
    return flows


def analyze(sources, findings: dict[str, CodeFinding]) -> None:
    """Run the flow check over scanned sources and record findings."""
    for src in sources:
        if isinstance(src, str) or src.vendor or len(src.text) > MAX_AST_FILE_BYTES:
            continue
        code = _js_of(src)
        if not code:
            continue
        try:
            flows = find_flows(code)
        except Exception:  # noqa: S112 - parser failure on hostile input must not abort the scan
            continue
        for line, snippet, _label in flows:
            record(
                findings,
                "CR-DEEP-FLOW",
                rule_id="CR-DEEP-FLOW",
                name="Sensitive data flows into a network call (AST)",
                category="EXFILTRATION",
                severity="HIGH",
                description=(
                    "Data from a sensitive source (cookies, history, storage, clipboard, "
                    "password fields) reaches fetch/sendBeacon/send within the same file. "
                    "Name-based taint, not a full analysis."
                ),
                count=1,
                location=Location(src.rel, line, snippet),
            )


def _js_of(src: SourceFile) -> str:
    if not src.is_html:
        return src.text
    from ..code_review import _INLINE_SCRIPT_RE

    return "\n".join(_INLINE_SCRIPT_RE.findall(src.text))
