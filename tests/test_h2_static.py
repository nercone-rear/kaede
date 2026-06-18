import pytest
from kaede.http.h2 import H2, H2_FORBIDDEN_HEADERS
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


class TestBuildResponseHeaders:
    def test_status_is_first_pseudo_header(self):
        resp = make_response(status=200)
        headers = H2.build_response_headers(resp)
        assert headers[0] == (":status", "200")

    def test_status_404(self):
        resp = make_response(status=404)
        headers = H2.build_response_headers(resp)
        assert headers[0] == (":status", "404")

    def test_normal_header_included(self):
        resp = make_response(status=200)
        resp.headers.set("Content-Type", "text/html")
        headers = H2.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert "content-type" in names

    def test_header_name_lowercased(self):
        resp = make_response(status=200)
        resp.headers.set("X-Custom-Header", "value")
        headers = H2.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert "x-custom-header" in names

    def test_forbidden_connection_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("Connection", "keep-alive")
        headers = H2.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert "connection" not in names

    def test_forbidden_transfer_encoding_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("Transfer-Encoding", "chunked")
        headers = H2.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert "transfer-encoding" not in names

    def test_all_forbidden_headers_filtered(self):
        resp = make_response(status=200)
        for h in H2_FORBIDDEN_HEADERS:
            resp.headers.set(h, "x")
        headers = H2.build_response_headers(resp)
        names = [n for n, _ in headers]
        for h in H2_FORBIDDEN_HEADERS:
            assert h not in names

    def test_header_injection_in_name_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("X-Evil\r\nInjected", "value")
        headers = H2.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert not any("injected" in n for n in names)

    def test_header_injection_in_value_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("X-Safe", "value\r\nEvil: injected")
        headers = H2.build_response_headers(resp)
        values = [v for _, v in headers]
        assert not any("injected" in v for v in values)

    def test_null_byte_in_name_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("X-\x00Bad", "value")
        headers = H2.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert not any("\x00" in n for n in names)

    def test_null_byte_in_value_filtered(self):
        resp = make_response(status=200)
        resp.headers.set("X-Test", "val\x00ue")
        headers = H2.build_response_headers(resp)
        values = [v for _, v in headers]
        assert not any("\x00" in v for v in values)

    def test_empty_response_only_status(self):
        resp = make_response(status=204)
        headers = H2.build_response_headers(resp)
        assert len(headers) == 1
        assert headers[0] == (":status", "204")

    def test_multiple_headers_included(self):
        resp = make_response(status=200)
        resp.headers.set("Content-Type", "application/json")
        resp.headers.set("Cache-Control", "no-cache")
        resp.headers.set("X-Request-Id", "abc")
        headers = H2.build_response_headers(resp)
        names = [n for n, _ in headers]
        assert "content-type" in names
        assert "cache-control" in names
        assert "x-request-id" in names


class TestBuildRequestHeaders:
    def test_method_pseudo_header(self):
        req = make_request(method="POST")
        headers = H2.build_request_headers(req, "example.com")
        assert (":method", "POST") in headers

    def test_scheme_pseudo_header(self):
        req = make_request(scheme="https")
        headers = H2.build_request_headers(req, "example.com")
        assert (":scheme", "https") in headers

    def test_authority_pseudo_header(self):
        req = make_request()
        headers = H2.build_request_headers(req, "example.com:443")
        assert (":authority", "example.com:443") in headers

    def test_path_pseudo_header(self):
        req = make_request(target="/api/users?q=1")
        headers = H2.build_request_headers(req, "example.com")
        assert (":path", "/api/users?q=1") in headers

    def test_host_header_filtered(self):
        req = make_request()
        req.headers.set("host", "example.com")
        headers = H2.build_request_headers(req, "example.com")
        names = [n for n, _ in headers]
        assert names.count("host") == 0

    def test_content_length_filtered(self):
        req = make_request()
        req.headers.set("content-length", "42")
        headers = H2.build_request_headers(req, "example.com")
        names = [n for n, _ in headers]
        assert "content-length" not in names

    def test_forbidden_headers_filtered(self):
        req = make_request()
        for h in H2_FORBIDDEN_HEADERS:
            req.headers.set(h, "x")
        headers = H2.build_request_headers(req, "example.com")
        names = [n for n, _ in headers]
        for h in H2_FORBIDDEN_HEADERS:
            assert h not in names

    def test_custom_header_included(self):
        req = make_request()
        req.headers.set("Authorization", "Bearer token123")
        headers = H2.build_request_headers(req, "example.com")
        names = [n for n, _ in headers]
        assert "authorization" in names

    def test_injection_in_name_filtered(self):
        req = make_request()
        req.headers.set("X-\r\nEvil", "v")
        headers = H2.build_request_headers(req, "example.com")
        names = [n for n, _ in headers]
        assert not any("evil" in n for n in names)

    def test_pseudo_headers_come_first(self):
        req = make_request(method="GET", target="/", scheme="https")
        req.headers.set("Accept", "*/*")
        headers = H2.build_request_headers(req, "example.com")
        pseudo = [n for n, _ in headers if n.startswith(":")]
        non_pseudo = [n for n, _ in headers if not n.startswith(":")]
        # All pseudo headers should appear before any non-pseudo header
        if pseudo and non_pseudo:
            last_pseudo_idx = max(i for i, (n, _) in enumerate(headers) if n.startswith(":"))
            first_non_pseudo_idx = min(i for i, (n, _) in enumerate(headers) if not n.startswith(":"))
            assert last_pseudo_idx < first_non_pseudo_idx


class TestBuildConnectWebSocketHeaders:
    def test_method_is_connect(self):
        req = make_request(target="/ws", scheme="https")
        headers = H2.build_connect_websocket_headers(req, "example.com")
        assert (":method", "CONNECT") in headers

    def test_protocol_is_websocket(self):
        req = make_request(target="/ws")
        headers = H2.build_connect_websocket_headers(req, "example.com")
        assert (":protocol", "websocket") in headers

    def test_websocket_version_header(self):
        req = make_request(target="/ws")
        headers = H2.build_connect_websocket_headers(req, "example.com")
        assert ("sec-websocket-version", "13") in headers

    def test_path_and_scheme(self):
        req = make_request(target="/chat", scheme="https")
        headers = H2.build_connect_websocket_headers(req, "example.com")
        assert (":path", "/chat") in headers
        assert (":scheme", "https") in headers

    def test_subprotocols_included(self):
        req = make_request(target="/ws")
        headers = H2.build_connect_websocket_headers(req, "example.com", subprotocols=["chat", "superchat"])
        assert ("sec-websocket-protocol", "chat, superchat") in headers

    def test_extensions_included(self):
        req = make_request(target="/ws")
        headers = H2.build_connect_websocket_headers(req, "example.com", extensions="permessage-deflate")
        assert ("sec-websocket-extensions", "permessage-deflate") in headers

    def test_no_subprotocols_skipped(self):
        req = make_request(target="/ws")
        headers = H2.build_connect_websocket_headers(req, "example.com", subprotocols=None)
        names = [n for n, _ in headers]
        assert "sec-websocket-protocol" not in names

    def test_host_filtered(self):
        req = make_request(target="/ws")
        req.headers.set("host", "example.com")
        headers = H2.build_connect_websocket_headers(req, "example.com")
        names = [n for n, _ in headers]
        assert "host" not in names

    def test_existing_sec_websocket_headers_filtered(self):
        req = make_request(target="/ws")
        req.headers.set("sec-websocket-key", "somekey")
        headers = H2.build_connect_websocket_headers(req, "example.com")
        names = [n for n, _ in headers]
        assert "sec-websocket-key" not in names

    def test_authority_set(self):
        req = make_request(target="/ws")
        headers = H2.build_connect_websocket_headers(req, "ws.example.com:443")
        assert (":authority", "ws.example.com:443") in headers
