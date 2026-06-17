import ipaddress
import pytest
from kaede.http.h1 import H1
from kaede.models import Request, Response, Headers

CLIENT = (ipaddress.IPv4Address("127.0.0.1"), 12345)

class TestH1ParseRequest:
    def _parse(self, raw: bytes, **kwargs):
        return H1.parse_request(raw, client=CLIENT, **kwargs)

    def test_simple_get(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = self._parse(raw)
        assert req.method == "GET"
        assert req.target == "/"
        assert req.headers.get("Host") == "example.com"
        assert req.body is None

    def test_post_with_body(self):
        body = b'{"key": "value"}'
        raw = (
            b"POST /api HTTP/1.1\r\n"
            b"Content-Length: 16\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n" + body
        )
        req = self._parse(raw)
        assert req.method == "POST"
        assert req.body == body

    def test_chunked_body(self):
        raw = (
            b"POST /upload HTTP/1.1\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nhello\r\n"
            b"6\r\n world\r\n"
            b"0\r\n\r\n"
        )
        req = self._parse(raw)
        assert req.body == b"hello world"

    def test_chunked_with_extension(self):
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5;ext=ignored\r\nhello\r\n"
            b"0\r\n\r\n"
        )
        req = self._parse(raw)
        assert req.body == b"hello"

    def test_empty_chunked_body(self):
        raw = b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        req = self._parse(raw)
        assert req.body is None

    def test_missing_header_terminator(self):
        with pytest.raises(ValueError, match="missing header terminator"):
            self._parse(b"GET / HTTP/1.1\r\nHost: example.com")

    def test_malformed_request_line(self):
        with pytest.raises(ValueError, match="malformed HTTP/1.1 request line"):
            self._parse(b"GETONLY\r\n\r\n")

    def test_unsupported_http_version(self):
        with pytest.raises(ValueError, match="unsupported HTTP version"):
            self._parse(b"GET / HTTP/1.0\r\n\r\n")

    def test_both_te_and_content_length(self):
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n5\r\nhello\r\n0\r\n\r\n"
        )
        with pytest.raises(ValueError):
            self._parse(raw)

    def test_max_body_size_enforced_content_length(self):
        body = b"x" * 100
        raw = b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n" + body
        with pytest.raises(ValueError, match="max_body_size"):
            self._parse(raw, max_body_size=50)

    def test_max_body_size_enforced_chunked(self):
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"64\r\n" + b"x" * 100 + b"\r\n"
            b"0\r\n\r\n"
        )
        with pytest.raises(ValueError, match="max_body_size"):
            self._parse(raw, max_body_size=50)

    def test_tls_info_propagated(self):
        from kaede.tls import TLSInfo
        raw = b"GET / HTTP/1.1\r\n\r\n"
        tls = TLSInfo(version="TLSv1.3", group=None, cipher=None)
        req = self._parse(raw, tls=tls)
        assert req.tls is tls

    def test_scheme_propagated(self):
        raw = b"GET / HTTP/1.1\r\n\r\n"
        req = self._parse(raw, scheme="https", secure=True)
        assert req.scheme == "https"
        assert req.secure is True

    def test_multiple_headers_same_name(self):
        raw = b"GET / HTTP/1.1\r\nAccept: text/html\r\nAccept: application/json\r\n\r\n"
        req = self._parse(raw)
        assert "text/html" in req.headers.get("Accept")
        assert "application/json" in req.headers.get("Accept")

class TestH1BuildResponse:
    def test_200_ok(self):
        r = Response(body=b"hello", status_code=200)
        r.headers.set("Content-Type", "text/plain")
        r.headers.set("Content-Length", "5")
        result = H1.build_response(r)
        assert isinstance(result, bytes)
        assert b"HTTP/1.1 200 OK" in result
        assert b"hello" in result

    def test_404_not_found(self):
        r = Response(body=b"not found", status_code=404)
        result = H1.build_response(r)
        assert b"HTTP/1.1 404 Not Found" in result

    def test_no_body_returns_tuple(self):
        r = Response(body=None, status_code=204)
        result = H1.build_response(r)
        assert isinstance(result, tuple)
        head, body = result
        assert b"HTTP/1.1 204" in head
        assert body is None

    def test_header_injection_filtered(self):
        r = Response(body=b"ok", status_code=200)
        r.headers.set("X-Evil", "value\r\nInjected: header")
        head = H1.build_response_head(r)
        assert b"Injected" not in head

    def test_unknown_status_code(self):
        r = Response(body=b"", status_code=999)
        head = H1.build_response_head(r)
        assert b"HTTP/1.1 999" in head

class TestH1BuildRequest:
    def test_basic_get(self):
        r = Request(method="GET", target="/path")
        r.headers.set("Host", "example.com")
        result = H1.build_request(r)
        assert b"GET /path HTTP/1.1\r\n" in result
        assert b"host: example.com\r\n" in result

    def test_post_with_body(self):
        r = Request(method="POST", target="/api", body=b"data")
        result = H1.build_request(r)
        assert b"POST /api HTTP/1.1\r\n" in result
        assert b"data" in result

class TestH1ParseResponse:
    def test_200_with_body(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        resp = H1.parse_response(raw)
        assert resp.status_code == 200
        assert resp.body == b"hello"

    def test_204_no_content(self):
        raw = b"HTTP/1.1 204 No Content\r\n\r\n"
        resp = H1.parse_response(raw)
        assert resp.status_code == 204
        assert resp.body is None

    def test_head_method_no_body(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        resp = H1.parse_response(raw, method="HEAD")
        assert resp.body is None

    def test_chunked_response(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nhello\r\n"
            b"0\r\n\r\n"
        )
        resp = H1.parse_response(raw)
        assert resp.body == b"hello"

    def test_incomplete_response(self):
        with pytest.raises(ValueError, match="missing header terminator"):
            H1.parse_response(b"HTTP/1.1 200 OK")

class TestH1DecodeChunked:
    def test_basic(self):
        data = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        result = H1.decode_chunked(data)
        assert result == b"hello world"

    def test_single_chunk(self):
        data = b"3\r\nabc\r\n0\r\n\r\n"
        assert H1.decode_chunked(data) == b"abc"

    def test_incomplete_returns_none(self):
        result = H1.scan_chunked(b"5\r\nhell")
        assert result is None

    def test_invalid_chunk_size(self):
        with pytest.raises(ValueError, match="invalid chunk size"):
            H1.decode_chunked(b"XY\r\nhello\r\n0\r\n\r\n")

    def test_missing_crlf_terminator(self):
        with pytest.raises(ValueError, match="missing CRLF terminator"):
            H1.decode_chunked(b"5\r\nhelloXX0\r\n\r\n")

class TestH1ResponseHasNoBody:
    @pytest.mark.parametrize("status,method,expected", [
        (200, "HEAD", True),
        (204, "GET", True),
        (304, "GET", True),
        (100, "GET", True),
        (199, "GET", True),
        (200, "GET", False),
        (201, "POST", False),
        (301, "GET", False)
    ])

    def test(self, status, method, expected):
        assert H1.response_has_no_body(status, method) is expected
