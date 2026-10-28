"""
Size-capped HTTP GET. Streams the body and aborts once max_bytes is exceeded,
so a hostile or misbehaving server cannot make us buffer an unbounded response.
"""

from __future__ import annotations

import requests

DEFAULT_MAX_BYTES = 2 * 1024 * 1024  # 2 MB: ample for store metadata APIs
_CHUNK = 64 * 1024


class ResponseTooLargeError(requests.RequestException):
    """Raised when a response body exceeds the allowed size.

    Subclasses RequestException so existing network-error handlers catch it.
    """


def get_limited(url: str, max_bytes: int = DEFAULT_MAX_BYTES, **kwargs) -> requests.Response:
    """requests.get() that refuses bodies larger than max_bytes."""
    resp = requests.get(url, stream=True, **kwargs)  # noqa: S113 - callers pass timeout
    try:
        declared = resp.headers.get("Content-Length", "")
        if declared.isdigit() and int(declared) > max_bytes:
            raise ResponseTooLargeError(f"Response from {url} exceeds {max_bytes} bytes")

        body = bytearray()
        for chunk in resp.iter_content(chunk_size=_CHUNK):
            body.extend(chunk)
            if len(body) > max_bytes:
                raise ResponseTooLargeError(f"Response from {url} exceeds {max_bytes} bytes")
    finally:
        resp.close()

    # Pre-populate the body so .text/.json()/.content work as with a normal response
    resp._content = bytes(body)
    resp._content_consumed = True
    return resp
