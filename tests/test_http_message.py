"""Message validation shared by HTTP/2 and HTTP/3.

Both versions carry the same abstract message over different framing, so RFC 9113 §8 and
RFC 9114 §4 say nearly the same things. The cases are written once and run against both, so
a rule that holds in one version and not the other shows up as a failure rather than as a
difference nobody notices.
"""

import pytest

from kaede.http.models import HTTPBroadRole, HTTPHeaders, HTTPResponse
from kaede.http.api.common import HTTPLimits
from kaede.http.protocol.h2 import H2Protocol, H2Connection, H2StreamError
from kaede.http.protocol.h3 import H3Protocol, H3Connection, H3Error

REQUEST = [(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a")]

class Peer:
    """One version's connection object, with the small shape differences smoothed over."""

    def __init__(self, name, build, error):
        self.name = name
        self.build = build
        self.error = error

    def __repr__(self):
        return self.name

def role(server):
    return HTTPBroadRole.SERVER if server else HTTPBroadRole.CLIENT

def h2(server=True):
    session = H2Protocol.__new__(H2Protocol)
    session.transport, session.limits, session.observer = object(), HTTPLimits(), None
    session.remote = type("Remote", (), {"initial_window_size": 65535})()

    return H2Connection(session, 1, role=role(server))

def h3(server=True):
    session = H3Protocol.__new__(H3Protocol)
    session.connection, session.limits, session.observer = object(), HTTPLimits(), None

    return H3Connection(session, None, role=role(server))

PEERS = [Peer("HTTP/2", h2, H2StreamError), Peer("HTTP/3", h3, H3Error)]

def split(connection, fields):
    return connection.split(fields, trailer=False)

def request(connection, fields):
    return connection.request_from(*split(connection, fields))

@pytest.fixture(params=PEERS, ids=repr)
def peer(request):
    return request.param

class TestFieldSection:
    def test_an_uppercase_field_name_is_malformed(self, peer):
        """RFC 9113 §8.2.1 and RFC 9114 §4.2 both make it malformed.

        Neither HPACK nor QPACK folds case, so a forbidden field compared by exact match is
        reachable simply by capitalising it, and both checks have to be present.
        """
        with pytest.raises(peer.error):
            split(peer.build(), REQUEST + [("Connection", "close")])

        with pytest.raises(peer.error):
            split(peer.build(), REQUEST + [("Transfer-Encoding", "chunked")])

    @pytest.mark.parametrize("name", ["connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection"])
    def test_a_connection_specific_field_is_malformed(self, peer, name):
        with pytest.raises(peer.error):
            split(peer.build(), REQUEST + [(name, "x")])

    def test_a_padded_field_value_is_malformed(self, peer):
        # §8.2.1 forbids leading and trailing whitespace. Stripping it instead hands on a
        # value the sender never wrote, which is a rewrite rather than a rejection.
        with pytest.raises(peer.error):
            split(peer.build(), REQUEST + [("x-a", " v")])

        with pytest.raises(peer.error):
            split(peer.build(), REQUEST + [("x-a", "v\t")])

    def test_a_control_character_in_a_value_is_malformed(self, peer):
        # The underlying check raises ValueError, which is not a protocol error and used to
        # travel out of the frame pump and end every concurrent stream on the connection.
        with pytest.raises(peer.error):
            split(peer.build(), REQUEST + [("x-a", "b\nx")])

    def test_te_may_only_ask_for_trailers(self, peer):
        with pytest.raises(peer.error):
            split(peer.build(), REQUEST + [("te", "gzip, chunked")])

        split(peer.build(), REQUEST + [("te", "trailers")])

    def test_a_pseudo_header_after_a_regular_one_is_malformed(self, peer):
        with pytest.raises(peer.error):
            split(peer.build(), [(":method", "GET"), ("x-a", "b"), (":path", "/")])

    def test_a_repeated_pseudo_header_is_malformed(self, peer):
        # RFC 9113 §8.3.1 and RFC 9114 §4.3.1 both allow exactly one value. Taking the last
        # one silently means an upstream that reads the first sees a different request.
        with pytest.raises(peer.error):
            split(peer.build(), REQUEST + [(":path", "/admin")])

class TestPseudoHeaders:
    @pytest.mark.parametrize("name", [":evil", ":status", ":protocol"])
    def test_an_undefined_request_pseudo_header_is_malformed(self, peer, name):
        with pytest.raises(peer.error):
            request(peer.build(), REQUEST + [(name, "x")])

    @pytest.mark.parametrize("missing", [":method", ":scheme", ":path"])
    def test_a_missing_request_pseudo_header_is_malformed(self, peer, missing):
        fields = [field for field in REQUEST if field[0] != missing]

        with pytest.raises(peer.error):
            request(peer.build(), fields)

    def test_an_empty_path_is_malformed(self, peer):
        with pytest.raises(peer.error):
            request(peer.build(), [(":method", "GET"), (":scheme", "https"), (":path", ""), (":authority", "a")])

class TestAuthority:
    """RFC 9113 §8.3.1: a recipient MUST NOT use Host to determine the target URI when
    :authority is present. Copying :authority into Host only when Host is absent inverts it."""

    def test_the_authority_wins_over_a_host(self, peer):
        message = request(peer.build(), [(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "real.example")])

        assert message.headers.get("Host") == "real.example"
        assert message.url.host == "real.example"

    def test_a_disagreeing_host_is_malformed(self, peer):
        with pytest.raises(peer.error):
            request(peer.build(), [
                (":method", "GET"), (":scheme", "https"), (":path", "/"),
                (":authority", "internal.example"), ("host", "attacker.example"),
            ])

    def test_a_matching_host_is_accepted(self, peer):
        message = request(peer.build(), [
            (":method", "GET"), (":scheme", "https"), (":path", "/"),
            (":authority", "a"), ("host", "a"),
        ])

        assert message.headers.get("Host") == "a"

    def test_a_request_with_neither_is_malformed(self, peer):
        with pytest.raises(peer.error):
            request(peer.build(), [(":method", "GET"), (":scheme", "https"), (":path", "/")])

    def test_a_repeated_host_is_malformed(self, peer):
        with pytest.raises(peer.error):
            request(peer.build(), [
                (":method", "GET"), (":scheme", "https"), (":path", "/"),
                ("host", "a"), ("host", "evil"),
            ])

    def test_an_invalid_authority_is_malformed(self, peer):
        with pytest.raises(peer.error):
            request(peer.build(), [(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "ev il")])

class TestConnect:
    """RFC 9113 §8.5 and RFC 9114 §4.4: CONNECT omits :scheme and :path and carries :authority."""

    def test_a_compliant_connect_is_accepted(self, peer):
        message = request(peer.build(), [(":method", "CONNECT"), (":authority", "a:443")])

        assert message.method == "CONNECT"
        assert message.headers.get("Host") == "a:443"

    def test_a_connect_carrying_a_path_is_malformed(self, peer):
        with pytest.raises(peer.error):
            request(peer.build(), [(":method", "CONNECT"), (":authority", "a"), (":path", "/")])

    def test_a_connect_carrying_a_scheme_is_malformed(self, peer):
        with pytest.raises(peer.error):
            request(peer.build(), [(":method", "CONNECT"), (":authority", "a"), (":scheme", "https")])

    def test_a_connect_without_an_authority_is_malformed(self, peer):
        with pytest.raises(peer.error):
            request(peer.build(), [(":method", "CONNECT")])

class TestTrailers:
    """RFC 9113 §8.1: a trailer section MUST NOT include pseudo-header fields, and the rules
    on connection-specific fields apply to it exactly as they do to a header section."""

    def test_a_pseudo_header_in_a_trailer_section_is_malformed(self, peer):
        with pytest.raises(peer.error):
            peer.build().trailer([(":status", "200")])

    @pytest.mark.parametrize("name", ["transfer-encoding", "content-length", "host"])
    def test_a_framing_field_in_a_trailer_section_is_malformed(self, peer, name):
        with pytest.raises(peer.error):
            peer.build().trailer([(name, "x")])

    def test_an_uppercase_name_in_a_trailer_section_is_malformed(self, peer):
        with pytest.raises(peer.error):
            peer.build().trailer([("X-Checksum", "abc")])

    def test_an_ordinary_trailer_is_accepted(self, peer):
        assert peer.build().trailer([("x-checksum", "abc")]).get("x-checksum") == "abc"

class TestStatus:
    @pytest.mark.parametrize("value", ["20", "2000", "\xb2", "+200", "", "abc"])
    def test_a_status_that_is_not_three_digits_is_malformed(self, peer, value):
        connection = peer.build(server=False)

        with pytest.raises(peer.error):
            connection.response_from({":status": value}, HTTPHeaders())

    def test_a_three_digit_status_is_read(self, peer):
        connection = peer.build(server=False)

        assert connection.response_from({":status": "200"}, HTTPHeaders()).status_code == 200

    def test_an_undefined_response_pseudo_header_is_malformed(self, peer):
        connection = peer.build(server=False)

        with pytest.raises(peer.error):
            connection.response_from({":status": "200", ":evil": "x"}, HTTPHeaders())

class TestContentLength:
    """RFC 9113 §8.1.1 and RFC 9114 §4.1.2: Content-Length must equal the sum of the DATA
    frame lengths. A message that fails this and is relayed onto HTTP/1.1 frames its body by
    the declared length, and the remainder is read as the next request."""

    def counted(self, peer, declared, received):
        connection = peer.build()
        message = HTTPResponse(status_code=200, headers=HTTPHeaders([("content-length", declared)]))

        if isinstance(connection, H3Connection):
            message.body = b"x" * received
        else:
            connection.counted = received

        return lambda: connection.verify(message)

    def test_a_disagreeing_length_is_malformed(self, peer):
        with pytest.raises(peer.error):
            self.counted(peer, "5", 100)()

    def test_an_agreeing_length_is_accepted(self, peer):
        self.counted(peer, "5", 5)()

    def test_a_malformed_length_is_malformed(self, peer):
        with pytest.raises(peer.error):
            self.counted(peer, "\xb2", 0)()

    def test_a_bodiless_response_may_still_state_a_length(self, peer):
        # §8.1.1 lets a 204 or a HEAD response carry the length its content would have had.
        connection = peer.build()
        message = HTTPResponse(status_code=204, headers=HTTPHeaders([("content-length", "5")]))

        if isinstance(connection, H3Connection):
            message.body = b""
        else:
            connection.counted = 0

        connection.verify(message)
