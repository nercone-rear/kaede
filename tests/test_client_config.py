import pytest
from kaede.api.client import Config, Handler, split_url, build_request


class TestSplitURL:
    def test_basic_http(self):
        scheme, host, port, target, authority = split_url("http://example.com/")
        assert scheme == "http"
        assert host == "example.com"
        assert port == 80
        assert target == "/"
        assert authority == "example.com"

    def test_basic_https(self):
        scheme, host, port, target, authority = split_url("https://example.com/path")
        assert scheme == "https"
        assert host == "example.com"
        assert port == 443
        assert target == "/path"
        assert authority == "example.com"

    def test_non_default_http_port(self):
        scheme, host, port, target, authority = split_url("http://example.com:8080/")
        assert port == 8080
        assert "8080" in authority

    def test_non_default_https_port(self):
        scheme, host, port, target, authority = split_url("https://example.com:8443/")
        assert port == 8443
        assert "8443" in authority

    def test_default_http_port_excluded_from_authority(self):
        _, _, _, _, authority = split_url("http://example.com/")
        assert ":80" not in authority

    def test_default_https_port_excluded_from_authority(self):
        _, _, _, _, authority = split_url("https://example.com/")
        assert ":443" not in authority

    def test_ws_scheme_becomes_http(self):
        scheme, host, port, target, authority = split_url("ws://example.com/ws")
        assert scheme == "http"
        assert port == 80

    def test_wss_scheme_becomes_https(self):
        scheme, host, port, target, authority = split_url("wss://example.com/ws")
        assert scheme == "https"
        assert port == 443

    def test_query_string_preserved(self):
        _, _, _, target, _ = split_url("http://example.com/search?q=hello&lang=en")
        assert target == "/search?q=hello&lang=en"

    def test_no_path_defaults_to_slash(self):
        _, _, _, target, _ = split_url("http://example.com")
        assert target == "/"

    def test_path_without_leading_slash(self):
        _, _, _, target, _ = split_url("http://example.com/api/v1")
        assert target == "/api/v1"

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError, match="unsupported URL scheme"):
            split_url("ftp://example.com/file")

    def test_missing_host_raises(self):
        with pytest.raises(ValueError, match="missing host"):
            split_url("http:///path")

    def test_ipv6_host(self):
        scheme, host, port, target, authority = split_url("http://[::1]:8080/")
        assert host == "::1"
        assert port == 8080
        assert "[::1]" in authority

    def test_returns_correct_host(self):
        _, host, _, _, _ = split_url("https://api.example.com/v1")
        assert host == "api.example.com"

    def test_uppercase_scheme_normalized(self):
        scheme, _, _, _, _ = split_url("HTTP://example.com/")
        assert scheme == "http"


class TestBuildRequest:
    def _config(self, **kwargs):
        return Config(**kwargs)

    def test_user_agent_set(self):
        config = self._config()
        request, _, _, _ = build_request("GET", "http://example.com/", config, None, None)
        assert "User-Agent" in request.headers

    def test_user_agent_is_kaede(self):
        config = self._config()
        request, _, _, _ = build_request("GET", "http://example.com/", config, None, None)
        assert "Kaede" in (request.headers.get("User-Agent") or "")

    def test_host_header_set(self):
        config = self._config()
        request, _, _, _ = build_request("GET", "http://example.com/", config, None, None)
        assert "Host" in request.headers

    def test_accept_header_set(self):
        config = self._config()
        request, _, _, _ = build_request("GET", "http://example.com/", config, None, None)
        assert request.headers.get("Accept") == "*/*"

    def test_method_uppercased(self):
        config = self._config()
        request, _, _, _ = build_request("get", "http://example.com/", config, None, None)
        assert request.method == "GET"

    def test_post_method_uppercased(self):
        config = self._config()
        request, _, _, _ = build_request("post", "http://example.com/", config, None, None)
        assert request.method == "POST"

    def test_accept_encoding_set_when_decompress_true(self):
        config = self._config(decompress=True)
        request, _, _, _ = build_request("GET", "http://example.com/", config, None, None)
        assert "Accept-Encoding" in request.headers

    def test_accept_encoding_not_set_when_decompress_false(self):
        config = self._config(decompress=False)
        request, _, _, _ = build_request("GET", "http://example.com/", config, None, None)
        assert "Accept-Encoding" not in request.headers

    def test_body_set(self):
        config = self._config()
        request, _, _, _ = build_request("POST", "http://example.com/", config, None, b"hello")
        assert request.body == b"hello"

    def test_no_body_is_none(self):
        config = self._config()
        request, _, _, _ = build_request("GET", "http://example.com/", config, None, None)
        assert request.body is None

    def test_custom_headers_merged(self):
        config = self._config()
        request, _, _, _ = build_request("GET", "http://example.com/", config, {"X-Custom": "value"}, None)
        assert request.headers.get("X-Custom") == "value"

    def test_scheme_http_propagated(self):
        config = self._config()
        request, _, _, _ = build_request("GET", "http://example.com/", config, None, None)
        assert request.scheme == "http"
        assert request.secure is False

    def test_scheme_https_propagated(self):
        config = self._config()
        request, _, _, _ = build_request("GET", "https://example.com/", config, None, None)
        assert request.scheme == "https"
        assert request.secure is True

    def test_returns_correct_host(self):
        config = self._config()
        _, host, _, _ = build_request("GET", "http://api.example.com/", config, None, None)
        assert host == "api.example.com"

    def test_returns_correct_port(self):
        config = self._config()
        _, _, port, _ = build_request("GET", "http://example.com:9000/", config, None, None)
        assert port == 9000

    def test_returns_correct_authority(self):
        config = self._config()
        _, _, _, authority = build_request("GET", "http://example.com:9000/", config, None, None)
        assert "9000" in authority

    def test_custom_user_agent_not_overridden(self):
        config = self._config()
        request, _, _, _ = build_request("GET", "http://example.com/", config, {"User-Agent": "MyClient/1.0"}, None)
        assert request.headers.get("User-Agent") == "MyClient/1.0"

    def test_target_from_url_path(self):
        config = self._config()
        request, _, _, _ = build_request("GET", "http://example.com/api/data?key=val", config, None, None)
        assert request.target == "/api/data?key=val"


class TestClientConfig:
    def test_default_decompress(self):
        assert Config().decompress is True

    def test_default_connect_timeout(self):
        assert Config().connect_timeout == 30

    def test_default_read_timeout(self):
        assert Config().read_timeout == 60

    def test_default_max_body_size(self):
        assert Config().max_body_size == 16 * 1024 * 1024

    def test_default_max_connections_per_host(self):
        assert Config().max_connections_per_host == 10

    def test_default_max_concurrent_streams(self):
        assert Config().max_concurrent_streams == 100

    def test_default_max_websocket_message_size(self):
        assert Config().max_websocket_message_size == 4 * 1024 * 1024

    def test_default_protocols_include_h1(self):
        assert "http/1.1" in Config().protocols

    def test_default_protocols_include_h2(self):
        assert "h2" in Config().protocols

    def test_default_protocols_include_h3(self):
        assert "h3" in Config().protocols

    def test_custom_decompress_false(self):
        assert Config(decompress=False).decompress is False

    def test_custom_connect_timeout(self):
        assert Config(connect_timeout=10.0).connect_timeout == 10.0

    def test_custom_read_timeout(self):
        assert Config(read_timeout=120.0).read_timeout == 120.0

    def test_user_agent_contains_kaede(self):
        assert "Kaede" in Config().user_agent


class TestHandlerOrderedKinds:
    def _handler(self, protocols):
        config = Config(protocols=protocols)
        return Handler(config)

    def test_h3_first_when_listed_first(self):
        handler = self._handler(["h3", "h2", "http/1.1"])
        kinds = handler.ordered_kinds()
        assert kinds[0] == "h3"

    def test_tls_present_for_h2_and_h1(self):
        handler = self._handler(["h2", "http/1.1"])
        kinds = handler.ordered_kinds()
        assert "tls" in kinds
        assert "h3" not in kinds

    def test_only_h3(self):
        handler = self._handler(["h3"])
        kinds = handler.ordered_kinds()
        assert kinds == ["h3"]
        assert "tls" not in kinds

    def test_only_http1(self):
        handler = self._handler(["http/1.1"])
        kinds = handler.ordered_kinds()
        assert "tls" in kinds
        assert "h3" not in kinds

    def test_only_h2(self):
        handler = self._handler(["h2"])
        kinds = handler.ordered_kinds()
        assert "tls" in kinds
        assert "h3" not in kinds

    def test_h3_before_tls(self):
        handler = self._handler(["h3", "h2", "http/1.1"])
        kinds = handler.ordered_kinds()
        h3_idx = kinds.index("h3")
        tls_idx = kinds.index("tls")
        assert h3_idx < tls_idx

    def test_empty_protocols(self):
        handler = self._handler([])
        kinds = handler.ordered_kinds()
        assert kinds == []

    def test_h3_after_h1_in_protocol_list(self):
        # When h1 comes first, tls should come before h3
        handler = self._handler(["http/1.1", "h3"])
        kinds = handler.ordered_kinds()
        tls_idx = kinds.index("tls")
        h3_idx = kinds.index("h3")
        assert tls_idx < h3_idx


class TestHandlerConnectionCount:
    def _handler(self):
        return Handler(Config())

    def test_empty_returns_zero(self):
        handler = self._handler()
        assert handler.connection_count(("http", "example.com", 80)) == 0

    def test_counts_only_matching_key(self):
        handler = self._handler()

        class FakeConn:
            def __init__(self, key):
                self.key = key

        handler.connections.add(FakeConn(("http", "example.com", 80)))
        handler.connections.add(FakeConn(("http", "other.com", 80)))
        assert handler.connection_count(("http", "example.com", 80)) == 1
        assert handler.connection_count(("http", "other.com", 80)) == 1
        assert handler.connection_count(("http", "missing.com", 80)) == 0

    def test_counts_multiple_connections_same_key(self):
        handler = self._handler()

        class FakeConn:
            def __init__(self, key):
                self.key = key

        key = ("https", "example.com", 443)
        handler.connections.add(FakeConn(key))
        handler.connections.add(FakeConn(key))
        assert handler.connection_count(key) == 2
