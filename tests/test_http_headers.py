import pytest

from kaede.http.models import HTTPHeaders, HTTPHeaderCase
from kaede.http.headers import Cookie, SetCookie, AcceptEncoding, ContentType, ETag, Link
from kaede.http.helpers.hsts import HSTSPolicy, HSTSStore

class TestHTTPHeaders:
    def test_lookups_fold_case(self):
        headers = HTTPHeaders([("Content-Type", "text/html")])

        assert headers.get("content-type") == "text/html"
        assert "CONTENT-TYPE" in headers

    def test_a_repeated_field_keeps_every_value(self):
        headers = HTTPHeaders()
        headers.append("Set-Cookie", "a=1")
        headers.append("Set-Cookie", "b=2")

        assert headers["set-cookie"] == ["a=1", "b=2"]
        assert headers.get("set-cookie") == "a=1"

    def test_set_replaces_and_override_false_keeps(self):
        headers = HTTPHeaders([("X", "1")])

        headers.set("X", "2", override=False)
        assert headers.get("X") == "1"

        headers.set("X", "3")
        assert headers["x"] == ["3"]

    def test_building_applies_the_case(self):
        headers = HTTPHeaders([("content-type", "text/html")], case=HTTPHeaderCase.TITLECASE)

        assert headers.build() == "Content-Type: text/html\r\n"

    def test_parsing_round_trips(self):
        headers = HTTPHeaders.parse("Host: example.com\r\nAccept: */*\r\n", "HTTP/1.1")

        assert headers.get("host") == "example.com"
        assert headers.get("accept") == "*/*"

    def test_a_control_character_in_a_value_is_rejected(self):
        with pytest.raises(ValueError):
            HTTPHeaders().append("X", "a\rb")

    def test_an_invalid_field_name_is_rejected(self):
        with pytest.raises(ValueError):
            HTTPHeaders().append("Bad Name", "value")

    def test_obsolete_folding_is_rejected(self):
        with pytest.raises(ValueError):
            HTTPHeaders.parse("Host: x\r\n continued\r\n", "HTTP/1.1")

    def test_whitespace_before_the_colon_is_rejected(self):
        with pytest.raises(ValueError):
            HTTPHeaders.parse("Host : x\r\n", "HTTP/1.1")

class TestCookies:
    def test_a_request_cookie_parses(self):
        cookie = Cookie("a=1; b=2")

        assert cookie.get("a") == "1"
        assert cookie.get("b") == "2"

    def test_a_request_cookie_builds(self):
        assert Cookie({"a": "1", "b": "2"}).build() == "a=1; b=2"

    def test_set_cookie_builds_with_attributes(self):
        value = SetCookie("sid", "abc", path="/", secure=True, httponly=True, samesite="Lax", max_age=60).build()

        assert value == "sid=abc; Max-Age=60; Path=/; Secure; HttpOnly; SameSite=Lax"

    def test_set_cookie_parses(self):
        cookie = SetCookie.parse("sid=abc; Path=/; HttpOnly; Max-Age=60; SameSite=lax")

        assert cookie.name == "sid" and cookie.value == "abc"
        assert cookie.path == "/" and cookie.httponly and cookie.max_age == 60 and cookie.samesite == "Lax"

    def test_an_invalid_cookie_value_is_rejected(self):
        with pytest.raises(ValueError):
            SetCookie("sid", "bad;value").build()

class TestAcceptEncoding:
    def test_parses_weights(self):
        accept = AcceptEncoding.parse("gzip, br;q=0.5, deflate;q=0")

        assert accept.quality("gzip") == 1.0
        assert accept.quality("br") == 0.5
        assert accept.acceptable("gzip") and accept.acceptable("br")
        assert not accept.acceptable("deflate")

    def test_a_wildcard_covers_unlisted_codings(self):
        accept = AcceptEncoding.parse("gzip, *;q=0.1")

        assert accept.acceptable("zstd")
        assert accept.quality("zstd") == 0.1

class TestContentType:
    def test_splits_essence_and_parameters(self):
        content = ContentType("text/html; charset=UTF-8; boundary=xyz")

        assert content.essence == "text/html"
        assert content.charset == "UTF-8"
        assert content.boundary == "xyz"

class TestLink:
    def test_parses_targets_and_parameters(self):
        link = Link.parse('</next>; rel="next", </prev>; rel=prev')

        assert link.raw[0] == ("/next", {"rel": "next"})
        assert link.raw[1] == ("/prev", {"rel": "prev"})

class TestHSTS:
    def test_a_policy_round_trips(self):
        policy = HSTSPolicy(max_age=3600, include_subdomains=True)

        assert policy.build() == "max-age=3600; includeSubDomains"
        assert HSTSPolicy.parse("max-age=3600; includeSubDomains").include_subdomains

    def test_a_host_is_remembered_and_expires(self):
        store = HSTSStore()
        store.learn("example.com", "max-age=100", secure=True, now=1000.0)

        assert store.secure("example.com", now=1050.0)
        assert not store.secure("example.com", now=1101.0)

    def test_subdomains_are_covered_only_when_asked(self):
        store = HSTSStore()
        store.learn("example.com", "max-age=100; includeSubDomains", secure=True, now=1000.0)

        assert store.secure("www.example.com", now=1050.0)

        store.learn("other.com", "max-age=100", secure=True, now=1000.0)
        assert not store.secure("www.other.com", now=1050.0)

    def test_the_header_is_ignored_over_plain_transport(self):
        store = HSTSStore()
        store.learn("example.com", "max-age=100", secure=False, now=1000.0)

        assert not store.secure("example.com", now=1050.0)

class TestHSTSPolicyValidity:
    """RFC 6797 §6.1: a header field that cannot be parsed is ignored.

    Reading a malformed header as a zero max-age deletes the stored policy instead, which
    turns any broken or truncated header into a downgrade path for the whole host.
    """

    @pytest.mark.parametrize("value", ["includeSubDomains", "max-age=abc", "", "preload", "max-age", "max-age=-5", "max-age=5; max-age=6"])
    def test_a_header_without_a_valid_max_age_is_not_a_policy(self, value):
        assert HSTSPolicy.parse(value) is None

    @pytest.mark.parametrize("value,age", [("max-age=100", 100), ('max-age="100"', 100), ("max-age=0", 0), ("Max-Age=7; includeSubDomains", 7)])
    def test_a_valid_header_is_read(self, value, age):
        assert HSTSPolicy.parse(value).max_age == age

    def test_a_broken_header_leaves_a_stored_policy_in_place(self):
        store = HSTSStore()
        store.learn("example.com", "max-age=31536000")

        store.learn("example.com", "includeSubDomains")
        store.learn("example.com", "max-age=abc")
        store.learn("example.com", "")

        assert store.secure("example.com")

    def test_a_zero_max_age_still_removes_the_policy(self):
        # §6.1.1: max-age=0 is the documented way to say the host is no longer a Known Host.
        store = HSTSStore()
        store.learn("example.com", "max-age=31536000")
        store.learn("example.com", "max-age=0")

        assert not store.secure("example.com")

class TestHSTSHosts:
    @pytest.mark.parametrize("host", ["192.0.2.1", "2001:db8::1", "[2001:db8::1]"])
    def test_an_ip_address_is_never_a_known_host(self, host):
        # §8.1.1: an IP address MUST NOT be recorded as a Known HSTS Host.
        store = HSTSStore()
        store.learn(host, "max-age=31536000")

        assert not store.secure(host)

    def test_a_name_is_compared_after_idna_and_case_folding(self):
        # §8.1 compares the canonicalised form, so the spelling used to store a policy must
        # not decide whether a later lookup finds it.
        store = HSTSStore()
        store.learn("EXAMPLE.com.", "max-age=31536000")

        assert store.secure("example.com")
        assert store.secure("Example.COM")

    def test_subdomains_are_only_covered_when_the_policy_says_so(self):
        store = HSTSStore()
        store.learn("example.com", "max-age=31536000")

        assert not store.secure("a.example.com")

        store.learn("example.com", "max-age=31536000; includeSubDomains")

        assert store.secure("a.example.com")
        assert not store.secure("notexample.com")

class TestSetCookieMaxAge:
    """RFC 6265 §5.2.2: a Max-Age that is not an optional "-" followed by digits is ignored."""

    @pytest.mark.parametrize("value", ["--5", "\xb2", "abc", "", "5-", "+5", "5.0"])
    def test_a_malformed_max_age_is_ignored_rather_than_raised(self, value):
        assert SetCookie.parse(f"a=b; Max-Age={value}").max_age is None

    @pytest.mark.parametrize("value,age", [("60", 60), ("-5", -5), ("0", 0)])
    def test_a_valid_max_age_is_read(self, value, age):
        assert SetCookie.parse(f"a=b; Max-Age={value}").max_age == age

class TestETagWeakness:
    """RFC 9110 §8.8.3 writes the weak indicator as %s"W/", which is case sensitive."""

    def test_the_indicator_is_case_sensitive(self):
        assert ETag('W/"abc"').weak
        assert not ETag('w/"abc"').weak

    def test_a_lowercase_indicator_does_not_weaken_a_comparison(self):
        # w/"abc" is an opaque tag in its own right, not a weak form of "abc".
        assert not ETag('w/"abc"').strong_match('"abc"')

    def test_a_strong_comparison_needs_both_sides_strong(self):
        assert ETag('"abc"').strong_match('"abc"')
        assert not ETag('W/"abc"').strong_match('"abc"')

    def test_a_weak_comparison_ignores_the_indicator(self):
        assert ETag('W/"abc"').weak_match('"abc"')

    @pytest.mark.parametrize("value,ok", [('"abc"', True), ('W/"abc"', True), ("abc", False), ('"', False), ("", False)])
    def test_the_syntax_requires_a_quoted_opaque_tag(self, value, ok):
        assert ETag(value).valid == ok
