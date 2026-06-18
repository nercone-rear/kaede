import pytest
from kaede.http.h3 import H3, H3_FORBIDDEN_HEADERS
from kaede.models import Request, Response, Headers


def make_response(status=200, body=b"", **header_kv):
    r = Response(body=body, status_code=status)
    for k, v in header_kv.items():
        r.headers.set(k.replace("_", "-"), v)
    return r


def make_request(method="GET", target="/", scheme="https", **header_kv):
    h = Headers({})
    for k, v in header_kv.items():
        h.set(k.replace("_", "-"), v)
    return Request(method=method, target=target, scheme=scheme, headers=h)


class TestH3BuildResponseHeaders:
    def test_status_is_first_pseudo_header(self):
        resp = make_response(status=200)
        headers = H3.build_response_headers(resp)
        assert headers[0] == (b":status", b"200")

    def test_status_404(self):
        resp = make_response(status=404)
        headers = H3.build_response_headers(resp)
        assert headers[0] == (b":status", b"404")

    def test_normal_header_included(self):
        resp = make_response(status=200)
        resp.headers.set("Content-Type", "text/html")
        headers = H3.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert b"content-type" in names

    def test_header_name_lowercased(self):
        resp = make_response(status=200)
        resp.headers.set("X-Custom-Header", "value")
        headers = H3.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert b"x-custom-header" in names

    def test_forbidden_connection_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("Connection", "keep-alive")
        headers = H3.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert b"connection" not in names

    def test_forbidden_transfer_encoding_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("Transfer-Encoding", "chunked")
        headers = H3.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert b"transfer-encoding" not in names

    def test_all_forbidden_headers_filtered(self):
        resp = make_response(status=200)
        for h in H3_FORBIDDEN_HEADERS:
            resp.headers.set(h, "x")
        headers = H3.build_response_headers(resp)
        names = [n for n, _ in headers]
        for h in H3_FORBIDDEN_HEADERS:
            assert h.encode("ascii") not in names

    def test_header_injection_in_name_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("X-Evil\r\nInjected", "value")
        headers = H3.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert not any(b"injected" in n for n in names)

    def test_header_injection_in_value_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("X-Safe", "value\r\nEvil: injected")
        headers = H3.build_response_headers(resp)
        values = [v for _, v in headers]
        assert not any(b"injected" in v for v in values)

    def test_null_byte_in_name_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("X-\x00Bad", "value")
        headers = H3.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert not any(b"\x00" in n for n in names)

    def test_null_byte_in_value_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("X-Test", "val\x00ue")
        headers = H3.build_response_headers(resp)
        values = [v for _, v in headers]
        assert not any(b"\x00" in v for v in values)

    def test_empty_response_only_status(self):
        resp = make_response(status=204)
        headers = H3.build_response_headers(resp)
        assert len(headers) == 1
        assert headers[0] == (b":status", b"204")

    def test_headers_are_bytes_tuples(self):
        resp = make_response(status=200)
        resp.headers.set("Content-Type", "text/plain")
        headers = H3.build_response_headers(resp)
        for name, value in headers:
            assert isinstance(name, bytes)
            assert isinstance(value, bytes)

    def test_multiple_headers_included(self):
        resp = make_response(status=200)
        resp.headers.set("Content-Type", "application/json")
        resp.headers.set("Cache-Control", "no-cache")
        resp.headers.set("X-Request-Id", "abc")
        headers = H3.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert b"content-type" in names
        assert b"cache-control" in names
        assert b"x-request-id" in names


class TestH3BuildRequestHeaders:
    def test_method_pseudo_header(self):
        req = make_request(method="POST")
        headers = H3.build_request_headers(req, "example.com")
        assert (b":method", b"POST") in headers

    def test_scheme_pseudo_header(self):
        req = make_request(scheme="https")
        headers = H3.build_request_headers(req, "example.com")
        assert (b":scheme", b"https") in headers

    def test_authority_pseudo_header(self):
        req = make_request()
        headers = H3.build_request_headers(req, "example.com:443")
        assert (b":authority", b"example.com:443") in headers

    def test_path_pseudo_header(self):
        req = make_request(target="/api/users?q=1")
        headers = H3.build_request_headers(req, "example.com")
        assert (b":path", b"/api/users?q=1") in headers

    def test_host_header_filtered(self):
        req = make_request()
        req.headers.set("host", "example.com")
        headers = H3.build_request_headers(req, "example.com")
        names = [n for n, _ in headers]
        assert b"host" not in names

    def test_content_length_filtered(self):
        req = make_request()
        req.headers.set("content-length", "42")
        headers = H3.build_request_headers(req, "example.com")
        names = [n for n, _ in headers]
        assert b"content-length" not in names

    def test_forbidden_headers_filtered(self):
        req = make_request()
        for h in H3_FORBIDDEN_HEADERS:
            req.headers.set(h, "x")
        headers = H3.build_request_headers(req, "example.com")
        names = [n for n, _ in headers]
        for h in H3_FORBIDDEN_HEADERS:
            assert h.encode("ascii") not in names

    def test_custom_header_included(self):
        req = make_request()
        req.headers.set("Authorization", "Bearer token123")
        headers = H3.build_request_headers(req, "example.com")
        names = [n for n, _ in headers]
        assert b"authorization" in names

    def test_injection_in_name_filtered(self):
        req = make_request()
        req.headers.set("X-\r\nEvil", "v")
        headers = H3.build_request_headers(req, "example.com")
        names = [n for n, _ in headers]
        assert not any(b"evil" in n for n in names)

    def test_headers_are_bytes_tuples(self):
        req = make_request()
        headers = H3.build_request_headers(req, "example.com")
        for name, value in headers:
            assert isinstance(name, bytes)
            assert isinstance(value, bytes)


class TestH3EncodeFrame:
    def test_returns_bytes(self):
        result = H3.encode_frame(0x0, b"data")
        assert isinstance(result, bytes)

    def test_frame_type_in_output(self):
        result = H3.encode_frame(0x1, b"payload")
        assert result[0:1] == b"\x01"

    def test_empty_payload(self):
        result = H3.encode_frame(0x4, b"")
        assert isinstance(result, bytes)
        assert len(result) >= 2

    def test_payload_appended(self):
        payload = b"hello"
        result = H3.encode_frame(0x0, payload)
        assert result.endswith(payload)


class TestH3EncodeSettings:
    def test_returns_bytes(self):
        result = H3.encode_settings()
        assert isinstance(result, bytes)

    def test_not_empty(self):
        result = H3.encode_settings()
        assert len(result) > 0

    def test_starts_with_settings_frame_type(self):
        # FRAME_SETTINGS = 0x4
        result = H3.encode_settings()
        assert result[0:1] == b"\x04"
