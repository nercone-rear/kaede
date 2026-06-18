import pytest

from kaede.models import Request, Response
from kaede.process import parse_accept_encoding, parse_range, error_response

class TestParseAcceptEncoding:
    def test_empty(self):
        assert parse_accept_encoding("") == {}

    def test_single(self):
        result = parse_accept_encoding("gzip")
        assert result == {"gzip": 1.0}

    def test_multiple(self):
        result = parse_accept_encoding("gzip, br, zstd")
        assert result["gzip"] == 1.0
        assert result["br"] == 1.0
        assert result["zstd"] == 1.0

    def test_q_value(self):
        result = parse_accept_encoding("gzip;q=0.8, br;q=1.0, zstd;q=0.5")
        assert result["gzip"] == pytest.approx(0.8)
        assert result["br"] == pytest.approx(1.0)
        assert result["zstd"] == pytest.approx(0.5)

    def test_wildcard(self):
        result = parse_accept_encoding("*")
        assert result["*"] == 1.0

    def test_q_zero(self):
        result = parse_accept_encoding("gzip;q=0")
        assert result["gzip"] == 0.0

    def test_invalid_q_defaults_to_zero(self):
        result = parse_accept_encoding("gzip;q=bad")
        assert result["gzip"] == 0.0

    def test_whitespace(self):
        result = parse_accept_encoding("  gzip  ,  br  ")
        assert "gzip" in result
        assert "br" in result

class TestParseRange:
    def test_basic_range(self):
        assert parse_range("bytes=0-99", 1000) == (0, 99)

    def test_open_ended(self):
        assert parse_range("bytes=500-", 1000) == (500, 999)

    def test_suffix(self):
        assert parse_range("bytes=-200", 1000) == (800, 999)

    def test_clamp_end(self):
        assert parse_range("bytes=0-9999", 100) == (0, 99)

    def test_start_beyond_total(self):
        assert parse_range("bytes=200-300", 100) is None

    def test_start_greater_than_end(self):
        assert parse_range("bytes=50-20", 100) is None

    def test_not_bytes(self):
        assert parse_range("tokens=0-100", 1000) is None

    def test_invalid_spec(self):
        assert parse_range("bytes=abc-def", 1000) is None

    def test_suffix_zero(self):
        assert parse_range("bytes=-0", 100) is None

    def test_multiple_ranges_uses_first(self):
        result = parse_range("bytes=0-10, 20-30", 1000)
        assert result == (0, 10)

    def test_exact_range_equal_to_total(self):
        assert parse_range("bytes=0-99", 100) == (0, 99)

    def test_single_byte(self):
        assert parse_range("bytes=0-0", 100) == (0, 0)

    def test_last_byte(self):
        assert parse_range("bytes=99-99", 100) == (99, 99)

    def test_empty_string_returns_none(self):
        assert parse_range("", 100) is None

    def test_zero_total_suffix(self):
        assert parse_range("bytes=-10", 0) is None

    def test_missing_dash_returns_none(self):
        assert parse_range("bytes=100", 200) is None

    def test_start_equals_end(self):
        assert parse_range("bytes=50-50", 100) == (50, 50)

    def test_very_large_suffix(self):
        assert parse_range("bytes=-10000", 100) == (0, 99)

class TestErrorResponse:
    def _make_config(self):
        from kaede.api.server import Config as ServerConfig
        return ServerConfig()

    def test_basic_error_response(self):
        config = self._make_config()
        req = Request(method="GET", target="/")
        resp = error_response(req, config)
        assert resp.status_code == 500
        assert resp.body == b"Internal Server Error"

    def test_error_response_has_content_length(self):
        config = self._make_config()
        req = Request(method="GET", target="/")
        resp = error_response(req, config)
        assert resp.headers.get("Content-Length") == str(len(b"Internal Server Error"))

    def test_error_response_head_strips_body(self):
        config = self._make_config()
        req = Request(method="HEAD", target="/")
        resp = error_response(req, config)
        assert resp.body is None

    def test_error_response_content_type_is_plain(self):
        config = self._make_config()
        req = Request(method="GET", target="/")
        resp = error_response(req, config)
        assert "text/plain" in (resp.headers.get("Content-Type") or "")

    def test_error_response_compression_disabled(self):
        config = self._make_config()
        req = Request(method="GET", target="/")
        resp = error_response(req, config)
        assert resp.compression is False

    def test_error_response_server_header(self):
        from kaede.api.server import Config as ServerConfig
        config = ServerConfig(server_name="TestServer")
        req = Request(method="GET", target="/")
        resp = error_response(req, config)
        assert resp.headers.get("Server") == "TestServer"
