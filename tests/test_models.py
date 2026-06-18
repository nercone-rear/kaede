import os
import ipaddress
from kaede.models import Headers, Request, Response, RawRequest, RawResponse, Callback

class TestHeaders:
    def test_case_insensitive_set_get(self):
        h = Headers({"Content-Type": "text/plain"})
        assert h.get("content-type") == "text/plain"
        assert h.get("Content-Type") == "text/plain"
        assert h.get("CONTENT-TYPE") == "text/plain"

    def test_set_override(self):
        h = Headers({"X-Foo": "a"})
        h.set("X-Foo", "b")
        assert h.get("x-foo") == "b"

    def test_set_no_override(self):
        h = Headers({"X-Foo": "a"})
        h.set("X-Foo", "b", override=False)
        assert h.get("x-foo") == "a"

    def test_append_multiple_values(self):
        h = Headers({})
        h.append("Set-Cookie", "a=1")
        h.append("Set-Cookie", "b=2")
        values = h.get("Set-Cookie")
        assert isinstance(values, list)
        assert "a=1" in values
        assert "b=2" in values

    def test_regular_multi_value_joined(self):
        h = Headers({})
        h.append("Accept", "text/html")
        h.append("Accept", "application/json")
        result = h.get("Accept")
        assert result == "text/html, application/json"

    def test_contains(self):
        h = Headers({"X-Custom": "val"})
        assert "X-Custom" in h
        assert "x-custom" in h
        assert "X-Missing" not in h

    def test_remove(self):
        h = Headers({"X-Foo": "bar"})
        h.remove("X-Foo")
        assert h.get("X-Foo") is None

    def test_items(self):
        h = Headers({"A": "1", "B": "2"})
        items = dict(h.items())
        assert items.get("a") == "1"
        assert items.get("b") == "2"

    def test_getitem_setitem(self):
        h = Headers({})
        h["X-Test"] = "hello"
        assert h["X-Test"] == "hello"
        assert h["x-test"] == "hello"

    def test_get_default(self):
        h = Headers({})
        assert h.get("Missing", "default") == "default"

    def test_append_vary(self):
        h = Headers({})
        h.append_vary("Accept-Encoding")
        assert h.get("Vary") == "Accept-Encoding"

    def test_append_vary_dedup(self):
        h = Headers({})
        h.append_vary("Accept-Encoding")
        h.append_vary("Accept-Encoding")
        vary = h.get("Vary")
        assert vary.count("Accept-Encoding") == 1

    def test_append_vary_multiple(self):
        h = Headers({})
        h.append_vary("Accept-Encoding")
        h.append_vary("Accept-Language")
        vary = h.get("Vary")
        assert "Accept-Encoding" in vary
        assert "Accept-Language" in vary

    def test_set_cookie_single_value_returns_list(self):
        h = Headers({})
        h.append("Set-Cookie", "session=abc")
        result = h.get("Set-Cookie")
        assert isinstance(result, list)
        assert result == ["session=abc"]

    def test_set_cookie_case_insensitive(self):
        h = Headers({})
        h.append("set-cookie", "x=1")
        assert isinstance(h.get("Set-Cookie"), list)

    def test_remove_nonexistent_is_silent(self):
        h = Headers({})
        h.remove("X-Does-Not-Exist")

    def test_items_multi_value_expands(self):
        h = Headers({})
        h.append("X-Multi", "a")
        h.append("X-Multi", "b")
        pairs = [(k, v) for k, v in h.items() if k == "x-multi"]
        assert len(pairs) == 2
        values = [v for _, v in pairs]
        assert "a" in values and "b" in values

    def test_getitem_missing_returns_none(self):
        h = Headers({})
        assert h["X-Missing"] is None

    def test_set_with_lowercase_key(self):
        h = Headers({})
        h.set("content-type", "text/plain")
        assert h.get("Content-Type") == "text/plain"
        assert h.get("content-type") == "text/plain"

    def test_append_vary_case_insensitive_dedup(self):
        h = Headers({})
        h.append_vary("Accept-Encoding")
        h.append_vary("accept-encoding")
        vary = h.get("Vary")
        assert vary.count("ncoding") == 1

    def test_append_vary_multiple_distinct(self):
        h = Headers({})
        h.append_vary("Accept-Encoding")
        h.append_vary("Accept-Language")
        h.append_vary("Origin")
        vary = h.get("Vary")
        assert "Accept-Encoding" in vary
        assert "Accept-Language" in vary
        assert "Origin" in vary

    def test_get_returns_default_for_missing(self):
        h = Headers({})
        assert h.get("X-Missing", "fallback") == "fallback"

    def test_get_default_none_for_missing(self):
        h = Headers({})
        assert h.get("X-Missing") is None

    def test_contains_after_remove(self):
        h = Headers({"X-Foo": "bar"})
        h.remove("X-Foo")
        assert "X-Foo" not in h
        assert "x-foo" not in h

    def test_set_no_override_keeps_original(self):
        h = Headers({"X-A": "original"})
        h.set("X-A", "new", override=False)
        assert h.get("X-A") == "original"

    def test_multiple_set_cookie_preserved_as_list(self):
        h = Headers({})
        for i in range(5):
            h.append("Set-Cookie", f"key{i}=val{i}")
        result = h.get("set-cookie")
        assert isinstance(result, list)
        assert len(result) == 5

    def test_items_returns_lowercase_keys(self):
        h = Headers({"Content-Type": "text/html", "X-Custom": "yes"})
        keys = [k for k, _ in h.items()]
        assert all(k == k.lower() for k in keys)

class TestRequest:
    def _make_request(self, **kwargs):
        defaults = dict(method="GET", target="/")
        defaults.update(kwargs)
        return Request(**defaults)

    def test_basic_fields(self):
        r = self._make_request(method="POST", target="/api/data")
        assert r.method == "POST"
        assert r.target == "/api/data"

    def test_is_websocket_upgrade_true(self):
        h = Headers({
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
        })
        r = self._make_request(headers=h)
        assert r.is_websocket_upgrade is True

    def test_is_websocket_upgrade_missing_key(self):
        h = Headers({
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
        })
        r = self._make_request(headers=h)
        assert r.is_websocket_upgrade is False

    def test_is_websocket_upgrade_wrong_version(self):
        h = Headers({
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "8",
        })
        r = self._make_request(headers=h)
        assert r.is_websocket_upgrade is False

    def test_default_client(self):
        r = self._make_request()
        assert r.client[0] == ipaddress.IPv4Address("0.0.0.0")
        assert r.client[1] == 0

    def test_websocket_connection_multi_token(self):
        h = Headers({
            "Upgrade": "websocket",
            "Connection": "keep-alive, Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
        })
        r = self._make_request(headers=h)
        assert r.is_websocket_upgrade is True

    def test_websocket_upgrade_value_case_insensitive(self):
        h = Headers({
            "Upgrade": "WebSocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
        })
        r = self._make_request(headers=h)
        assert r.is_websocket_upgrade is True

    def test_websocket_false_without_upgrade_header(self):
        r = self._make_request()
        assert r.is_websocket_upgrade is False

    def test_websocket_false_wrong_upgrade_value(self):
        h = Headers({
            "Upgrade": "h2c",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
        })
        r = self._make_request(headers=h)
        assert r.is_websocket_upgrade is False

    def test_websocket_false_no_connection_header(self):
        h = Headers({
            "Upgrade": "websocket",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
        })
        r = self._make_request(headers=h)
        assert r.is_websocket_upgrade is False

    def test_ipv6_client(self):
        addr = ipaddress.IPv6Address("::1")
        r = self._make_request(client=(addr, 8080))
        assert r.client[0] == addr
        assert r.client[1] == 8080

    def test_default_scheme_is_http(self):
        r = self._make_request()
        assert r.scheme == "http"

    def test_default_secure_is_false(self):
        r = self._make_request()
        assert r.secure is False

    def test_default_protocol(self):
        r = self._make_request()
        assert r.protocol == "HTTP/1.1"

    def test_default_body_is_none(self):
        r = self._make_request()
        assert r.body is None

    def test_all_http_methods_constructible(self):
        for method in ("GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"):
            r = self._make_request(method=method)
            assert r.method == method

class TestResponse:
    def test_has_real_body_bytes(self):
        r = Response(body=b"hello")
        assert r.has_real_body is True

    def test_has_real_body_none(self):
        r = Response(body=None)
        assert r.has_real_body is False

    def test_has_real_body_non_bytes(self):
        async def gen():
            yield b"chunk"
        r = Response(body=gen())
        assert r.has_real_body is False

    def test_is_streaming(self):
        async def gen():
            yield b"chunk"
        r = Response(body=gen())
        assert r.is_streaming is True

    def test_is_not_streaming(self):
        r = Response(body=b"data")
        assert r.is_streaming is False

    def test_default_status_code(self):
        r = Response()
        assert r.status_code == 200

    def test_default_compression_on(self):
        r = Response()
        assert r.compression is True

    def test_default_minification_off(self):
        r = Response()
        assert r.minification is False

    def test_pathlike_body_is_not_streaming(self):
        r = Response(body=os.path.join("some", "file.txt"))
        assert r.is_streaming is False

    def test_pathlike_body_is_not_real_body(self):
        r = Response(body=os.path.join("some", "file.txt"))
        assert r.has_real_body is False

    def test_none_body_is_not_streaming(self):
        r = Response(body=None)
        assert r.is_streaming is False

    def test_default_content_type_is_none(self):
        r = Response()
        assert r.content_type is None

    def test_default_protocol(self):
        r = Response()
        assert r.protocol == "HTTP/1.1"

    def test_empty_bytes_body_is_real(self):
        r = Response(body=b"")
        assert r.has_real_body is True

    def test_is_not_streaming_with_bytes(self):
        r = Response(body=b"data")
        assert r.is_streaming is False

class TestRawRequest:
    def test_defaults(self):
        rs = RawRequest()
        assert rs.method == ""
        assert rs.target == ""
        assert rs.scheme == "https"
        assert rs.authority == ""
        assert isinstance(rs.headers, Headers)
        assert isinstance(rs.body, bytearray)
        assert len(rs.body) == 0

    def test_custom_fields(self):
        rs = RawRequest(method="POST", target="/upload", authority="example.com")
        assert rs.method == "POST"
        assert rs.target == "/upload"
        assert rs.authority == "example.com"

class TestRawResponse:
    def test_defaults(self):
        rs = RawResponse()
        assert rs.status_code == 0
        assert isinstance(rs.headers, Headers)
        assert isinstance(rs.body, bytearray)
        assert len(rs.body) == 0

    def test_custom_fields(self):
        rs = RawResponse(status_code=200)
        assert rs.status_code == 200
