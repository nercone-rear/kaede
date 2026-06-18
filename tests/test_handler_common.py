"""
negotiate_websocket() conformance tests.

RFC 6455 §4.2.1 — subprotocol negotiation
RFC 7692    — permessage-deflate extension negotiation
"""
from __future__ import annotations

import pytest

from kaede.models import Request, Headers
from kaede.websocket import PerMessageDeflate
from kaede.handler.common import negotiate_websocket

def _req(*, subprotocol_header: str | None = None, extensions_header: str | None = None) -> Request:
    """Build a minimal Request with optional WebSocket negotiation headers."""
    h: dict[str, str] = {"Host": "example.com"}
    if subprotocol_header is not None:
        h["Sec-WebSocket-Protocol"] = subprotocol_header
    if extensions_header is not None:
        h["Sec-WebSocket-Extensions"] = extensions_header
    return Request(method="GET", target="/ws", headers=Headers(h))

# RFC 6455 §4.2.2: subprotocol selection

class TestNegotiateWebSocketSubprotocol:
    def test_no_offered_subprotocols_returns_none(self):
        """If the client offers no subprotocols, the result must be None."""
        req = _req()
        sub, _ = negotiate_websocket(req, ["chat"])
        assert sub is None

    def test_empty_offered_list_returns_none(self):
        req = _req(subprotocol_header="")
        sub, _ = negotiate_websocket(req, ["chat"])
        assert sub is None

    def test_matching_subprotocol_returned(self):
        """RFC 6455 §4.2.2: Server must respond with one of the offered subprotocols."""
        req = _req(subprotocol_header="chat")
        sub, _ = negotiate_websocket(req, ["chat"])
        assert sub == "chat"

    def test_selected_subprotocol_is_from_client_offer(self):
        """RFC 6455 §4.2.2: The selected subprotocol MUST be one the client offered."""
        req = _req(subprotocol_header="chat, superchat")
        sub, _ = negotiate_websocket(req, ["chat", "superchat"])
        assert sub in ("chat", "superchat")

    def test_no_common_subprotocol_returns_none(self):
        """If no overlap exists between client and server lists, result must be None."""
        req = _req(subprotocol_header="graphql-ws")
        sub, _ = negotiate_websocket(req, ["chat"])
        assert sub is None

    def test_first_server_match_wins(self):
        """Server's preference order determines selection."""
        req = _req(subprotocol_header="a, b, c")
        # Server only supports 'b'; 'a' and 'c' are not supported.
        sub, _ = negotiate_websocket(req, ["b"])
        assert sub == "b"

    def test_server_list_empty_returns_none(self):
        req = _req(subprotocol_header="chat")
        sub, _ = negotiate_websocket(req, [])
        assert sub is None

    def test_subprotocol_with_leading_trailing_spaces_stripped(self):
        """Token values in the header may be surrounded by whitespace."""
        req = _req(subprotocol_header=" chat , superchat ")
        sub, _ = negotiate_websocket(req, ["chat"])
        assert sub == "chat"

# RFC 7692 §6.1: permessage-deflate extension negotiation

class TestNegotiateWebSocketDeflate:
    def test_no_extensions_header_returns_no_deflate(self):
        """Without Sec-WebSocket-Extensions, deflate must not be negotiated."""
        req = _req()
        _, deflate = negotiate_websocket(req, [])
        assert deflate is None

    def test_permessage_deflate_offered_returns_deflate(self):
        """RFC 7692 §6.1: If client offers permessage-deflate, server should accept."""
        req = _req(extensions_header="permessage-deflate")
        _, deflate = negotiate_websocket(req, [])
        assert isinstance(deflate, PerMessageDeflate)

    def test_unrecognized_extension_returns_no_deflate(self):
        req = _req(extensions_header="x-unknown-extension")
        _, deflate = negotiate_websocket(req, [])
        assert deflate is None

    def test_client_no_context_takeover_parsed(self):
        """RFC 7692 §6.1: client_no_context_takeover param must be parsed."""
        req = _req(extensions_header="permessage-deflate; client_no_context_takeover")
        _, deflate = negotiate_websocket(req, [])
        assert deflate is not None
        assert deflate.client_no_context_takeover is True

    def test_server_max_window_bits_clamped(self):
        """RFC 7692 §6.1: server_max_window_bits must be clamped to [8, 15]."""
        req = _req(extensions_header="permessage-deflate; server_max_window_bits=10")
        _, deflate = negotiate_websocket(req, [])
        assert deflate is not None
        assert 8 <= deflate.server_max_window_bits <= 15

    def test_client_max_window_bits_clamped(self):
        req = _req(extensions_header="permessage-deflate; client_max_window_bits=9")
        _, deflate = negotiate_websocket(req, [])
        assert deflate is not None
        assert 8 <= deflate.client_max_window_bits <= 15

    def test_multiple_extensions_with_permessage_deflate(self):
        """permessage-deflate mixed with other extensions: must still be negotiated."""
        req = _req(extensions_header="x-other, permessage-deflate; client_no_context_takeover")
        _, deflate = negotiate_websocket(req, [])
        assert deflate is not None

    def test_subprotocol_and_deflate_independent(self):
        """Subprotocol and deflate negotiation are independent."""
        req = _req(
            subprotocol_header="chat",
            extensions_header="permessage-deflate",
        )
        sub, deflate = negotiate_websocket(req, ["chat"])
        assert sub == "chat"
        assert deflate is not None
