import ipaddress
from kaede.models import Headers, Request, Response

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
