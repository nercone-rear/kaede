import ipaddress

import pytest

from kaede.ip import IPVersion
from kaede.url import URL

class TestParsing:
    def test_parses_every_component(self):
        url = URL.parse("https://example.com:8443/a/b?x=1&y=2#top")

        assert url.scheme == "https"
        assert url.host == "example.com"
        assert url.port == 8443
        assert url.path == "/a/b"
        assert url.query == "x=1&y=2"
        assert url.fragment == "top"

    def test_the_port_is_optional(self):
        assert URL.parse("https://example.com/").port is None

    def test_an_invalid_port_is_rejected(self):
        with pytest.raises(ValueError):
            URL.parse("https://example.com:99999/").port

    def test_an_ipv6_host_loses_its_brackets(self):
        url = URL.parse("http://[2001:db8::1]:8080/x")

        assert url.host == "2001:db8::1"
        assert url.port == 8080

class TestBuilding:
    def test_round_trips(self):
        value = "https://example.com:8443/a/b?x=1&y=2#top"
        assert str(URL.parse(value)) == value

    def test_an_empty_path_becomes_the_root(self):
        assert str(URL.parse("https://example.com")) == "https://example.com/"

    def test_a_default_port_is_omitted(self):
        # RFC 3986 section 6.2.3: the default port is equivalent to none at all.
        assert str(URL.parse("https://example.com:443/")) == "https://example.com/"
        assert str(URL.parse("http://example.com:80/")) == "http://example.com/"

    def test_a_distinct_port_is_kept(self):
        assert URL.parse("https://example.com:8443/").netloc == "example.com:8443"

    def test_an_ipv6_host_is_bracketed(self):
        assert URL.parse("http://[2001:db8::1]:8080/x").netloc == "[2001:db8::1]:8080"

class TestParams:
    def test_splits_pairs(self):
        assert URL.parse("http://e/?a=1&b=2").params == {"a": ["1"], "b": ["2"]}

    def test_keeps_every_value_of_a_repeated_name(self):
        assert URL.parse("http://e/?a=1&a=2").params == {"a": ["1", "2"]}

    def test_percent_decodes(self):
        assert URL.parse("http://e/?na%20me=v%2Falue").params == {"na me": ["v/alue"]}

    def test_a_name_without_a_value(self):
        assert URL.parse("http://e/?flag").params == {"flag": [""]}

    def test_an_empty_query(self):
        assert URL.parse("http://e/").params == {}

class TestTargets:
    def test_origin_form(self):
        # RFC 9112 section 3.2.1, the common request form.
        url = URL.from_target("/index.html?q=1", "https", "example.com:8443")

        assert url.scheme == "https"
        assert url.host == "example.com"
        assert url.port == 8443
        assert url.path == "/index.html"
        assert url.query == "q=1"

    def test_an_origin_form_double_slash_stays_in_the_path(self):
        # RFC 9112 section 3.2.1: an origin-form target is a literal
        # absolute-path, so a leading "//host" must not be reinterpreted as an
        # authority. Otherwise url.path ("/path") would disagree with the target
        # on the wire ("//evil.example/path"), a path-confusion primitive.
        url = URL.from_target("//evil.example/path", "https", "example.com")

        assert url.host == "example.com"
        assert url.path == "//evil.example/path"
        assert url.query == ""

    def test_absolute_form(self):
        url = URL.from_target("http://other.example/x", "https", "example.com")

        assert url.scheme == "http"
        assert url.host == "other.example"
        assert url.path == "/x"

    def test_authority_form(self):
        # RFC 9112 section 3.2.3, only used by CONNECT.
        url = URL.from_target("tunnel.example:443", "https", "example.com")

        assert url.host == "tunnel.example"
        assert url.port == 443
        assert url.path == ""

    def test_asterisk_form(self):
        # RFC 9112 section 3.2.4, only used by OPTIONS.
        url = URL.from_target("*", "https", "example.com")

        assert url.host == "example.com"
        assert url.path == "*"

class TestIPVersion:
    def test_recognizes_both_families(self):
        assert IPVersion.from_address(ipaddress.IPv4Address("192.0.2.1")) == IPVersion.IPv4
        assert IPVersion.from_address(ipaddress.IPv6Address("2001:db8::1")) == IPVersion.IPv6

    def test_rejects_anything_else(self):
        with pytest.raises(ValueError):
            IPVersion.from_address("192.0.2.1")
