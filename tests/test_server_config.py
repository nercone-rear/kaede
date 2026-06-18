import pytest
from kaede.api.server import Config, Server
from kaede.models import Callback


def _server(config=None):
    return Server(Callback(), config or Config())


class TestServerConfig:
    def test_default_server_name(self):
        assert Config().server_name == "Kaede"

    def test_custom_server_name(self):
        assert Config(server_name="MyApp").server_name == "MyApp"

    def test_default_protocols_include_h2_and_h1(self):
        cfg = Config()
        assert "h2" in cfg.protocols
        assert "http/1.1" in cfg.protocols

    def test_default_keepalive_timeout(self):
        assert Config().keepalive_timeout == 75

    def test_default_max_header_size(self):
        assert Config().max_header_size == 64 * 1024

    def test_default_max_body_size(self):
        assert Config().max_body_size == 16 * 1024 * 1024

    def test_default_workers(self):
        assert Config().workers == 1

    def test_default_max_concurrent_streams(self):
        assert Config().max_concurrent_streams == 100

    def test_default_minification_all_off(self):
        cfg = Config()
        assert cfg.minify_html is False
        assert cfg.minify_css is False
        assert cfg.minify_js is False
        assert cfg.minify_svg is False

    def test_custom_max_body_size(self):
        cfg = Config(max_body_size=1024)
        assert cfg.max_body_size == 1024

    def test_custom_protocols(self):
        cfg = Config(protocols=["http/1.1"])
        assert "http/1.1" in cfg.protocols
        assert "h2" not in cfg.protocols

    def test_default_bind_http(self):
        cfg = Config()
        assert len(cfg.bind_http) > 0

    def test_default_bind_https_empty(self):
        cfg = Config()
        assert cfg.bind_https == []

    def test_minification_can_be_enabled(self):
        cfg = Config(minify_html=True, minify_css=True)
        assert cfg.minify_html is True
        assert cfg.minify_css is True


class TestParseHostPort:
    def test_ipv4_host_and_port(self):
        s = _server()
        host, port = s.parse_host_port("127.0.0.1:8080")
        assert host == "127.0.0.1"
        assert port == 8080

    def test_ipv4_port_80(self):
        s = _server()
        host, port = s.parse_host_port("0.0.0.0:80")
        assert host == "0.0.0.0"
        assert port == 80

    def test_ipv6_bracketed(self):
        s = _server()
        host, port = s.parse_host_port("[::1]:443")
        assert host == "::1"
        assert port == 443

    def test_ipv6_full_address(self):
        s = _server()
        host, port = s.parse_host_port("[2001:db8::1]:8443")
        assert host == "2001:db8::1"
        assert port == 8443

    def test_hostname_and_port(self):
        s = _server()
        host, port = s.parse_host_port("example.com:9000")
        assert host == "example.com"
        assert port == 9000

    def test_missing_port_raises(self):
        s = _server()
        with pytest.raises(ValueError):
            s.parse_host_port("127.0.0.1")

    def test_missing_port_no_colon_raises(self):
        s = _server()
        with pytest.raises((ValueError, Exception)):
            s.parse_host_port("localhost")

    def test_port_443(self):
        s = _server()
        host, port = s.parse_host_port("example.com:443")
        assert port == 443

    def test_port_is_int(self):
        s = _server()
        _, port = s.parse_host_port("127.0.0.1:1234")
        assert isinstance(port, int)


class TestServerListeners:
    def test_parse_host_port_consistency(self):
        s = _server(Config(bind_http=["127.0.0.1:18080"], bind_https=[]))
        host, port = s.parse_host_port("127.0.0.1:18080")
        assert host == "127.0.0.1"
        assert port == 18080


class TestServerConfigExtra:
    def test_default_shutdown_timeout(self):
        assert Config().shutdown_timeout == 30

    def test_default_auto_restart(self):
        assert Config().auto_restart is True

    def test_default_max_stream_buffer_size(self):
        assert Config().max_stream_buffer_size == 1024 * 1024

    def test_default_max_pipeline_buffer_len(self):
        assert Config().max_pipeline_buffer_len == 100

    def test_default_max_stream_resets(self):
        assert Config().max_stream_resets == 1000

    def test_default_max_websocket_message_size(self):
        assert Config().max_websocket_message_size == 4 * 1024 * 1024

    def test_default_minify_keep_html_comments(self):
        assert Config().minify_keep_html_comments is False

    def test_default_bind_unix_empty(self):
        assert Config().bind_unix == []

    def test_default_bind_quic_empty(self):
        assert Config().bind_quic == []

    def test_custom_shutdown_timeout(self):
        assert Config(shutdown_timeout=60).shutdown_timeout == 60

    def test_custom_auto_restart_false(self):
        assert Config(auto_restart=False).auto_restart is False

    def test_custom_max_websocket_message_size(self):
        assert Config(max_websocket_message_size=1024).max_websocket_message_size == 1024

    def test_custom_max_stream_resets(self):
        assert Config(max_stream_resets=500).max_stream_resets == 500

    def test_minify_keep_html_comments_can_be_enabled(self):
        cfg = Config(minify_keep_html_comments=True)
        assert cfg.minify_keep_html_comments is True

    def test_custom_max_pipeline_buffer_len(self):
        assert Config(max_pipeline_buffer_len=50).max_pipeline_buffer_len == 50


class TestServerParseHostPortEdgeCases:
    def test_port_zero(self):
        s = _server()
        host, port = s.parse_host_port("127.0.0.1:0")
        assert port == 0

    def test_ipv6_loopback(self):
        s = _server()
        host, port = s.parse_host_port("[::1]:80")
        assert host == "::1"
        assert port == 80

    def test_ipv6_any(self):
        s = _server()
        host, port = s.parse_host_port("[::]:8080")
        assert host == "::"
        assert port == 8080

    def test_subdomain_host(self):
        s = _server()
        host, port = s.parse_host_port("api.example.com:443")
        assert host == "api.example.com"
        assert port == 443

    def test_high_port(self):
        s = _server()
        host, port = s.parse_host_port("127.0.0.1:65535")
        assert port == 65535
