import pytest
import requests
import responses

from extanalyze.core.http import ResponseTooLargeError, get_limited

URL = "https://example.test/data"


@responses.activate
def test_small_response_ok():
    responses.add(responses.GET, URL, body='{"a": 1}')
    resp = get_limited(URL, max_bytes=100)
    assert resp.json() == {"a": 1}
    assert resp.status_code == 200


@responses.activate
def test_oversized_body_rejected():
    responses.add(responses.GET, URL, body=b"x" * 500)
    with pytest.raises(ResponseTooLargeError):
        get_limited(URL, max_bytes=100)


@responses.activate
def test_error_is_requests_exception():
    responses.add(responses.GET, URL, body=b"x" * 500)
    with pytest.raises(requests.RequestException):
        get_limited(URL, max_bytes=100)
