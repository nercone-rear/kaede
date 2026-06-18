"""
End-to-end HTTP/3 request/response over the in-process loopback harness
(real QUIC-TLS handshake, QPACK, framing, and the server request pipeline).
"""
from __future__ import annotations

from kaede.models import Response, Callback

class EchoCallback(Callback):
    async def on_request(self, request):
        if request.method == "POST":
            return Response(b"got:" + (request.body or b""), content_type="text/plain")
        return Response(b"hello h3", content_type="text/plain")

class TestRequestResponse:
    async def test_get(self, h3_loopback):
        lb = h3_loopback(EchoCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.status_code == 200
        assert resp.body == b"hello h3"

    async def test_post_with_body(self, h3_loopback):
        lb = h3_loopback(EchoCallback())
        await lb.handshake()
        resp = await lb.request("POST", "/submit", body=b"payload")
        assert resp.status_code == 200
        assert resp.body == b"got:payload"

    async def test_headers_round_trip(self, h3_loopback):
        class HeaderCallback(Callback):
            async def on_request(self, request):
                return Response(b"ok", headers=__import__("kaede.models", fromlist=["Headers"]).Headers({"X-Custom": "v1"}), content_type="text/plain")

        lb = h3_loopback(HeaderCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.headers.get("x-custom") == "v1"
