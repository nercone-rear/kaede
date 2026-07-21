import pickle
import sys

import pytest

from kaede.uds import UDSPort

# POSIX defines the UDS bind path through struct sockaddr_un.sun_path, whose
# size is platform dependent (104 bytes on BSD/Darwin, 108 on Linux) and always
# reserves at least one byte for the implementation's null terminator.

class TestValidation:
    def test_accepts_a_path(self):
        assert UDSPort("/tmp/kaede.sock") == "/tmp/kaede.sock"

    def test_defaults_to_empty(self):
        assert UDSPort() == ""

    def test_accepts_the_longest_permitted_path(self):
        value = "/" + "a" * (UDSPort.limit - 1)
        assert len(value.encode()) == UDSPort.limit
        assert UDSPort(value) == value

    def test_rejects_a_path_beyond_the_limit(self):
        value = "/" + "a" * UDSPort.limit

        with pytest.raises(ValueError):
            UDSPort(value)

    @pytest.mark.parametrize("value", [None, 80, 80.0, b"/tmp/kaede.sock", ["/tmp/kaede.sock"]])
    def test_rejects_non_string(self, value):
        with pytest.raises(TypeError):
            UDSPort(value)

    def test_the_limit_matches_the_current_platform(self):
        assert UDSPort.limit == (103 if sys.platform == "darwin" else 107)

class TestBehaviour:
    def test_is_a_string(self):
        assert isinstance(UDSPort("/tmp/a.sock"), str)

    def test_compares_and_hashes_as_a_string(self):
        assert UDSPort("/tmp/a.sock") == "/tmp/a.sock"
        assert hash(UDSPort("/tmp/a.sock")) == hash("/tmp/a.sock")
        assert {UDSPort("/tmp/a.sock"): "yes"}["/tmp/a.sock"] == "yes"

    def test_survives_pickling(self):
        assert pickle.loads(pickle.dumps(UDSPort("/tmp/a.sock"))) == UDSPort("/tmp/a.sock")

    def test_repr_names_the_type(self):
        assert repr(UDSPort("/tmp/a.sock")) == "UDSPort('/tmp/a.sock')"

    def test_dynamic_is_only_the_empty_address(self):
        assert UDSPort("").dynamic
        assert not UDSPort("/tmp/a.sock").dynamic

    def test_abstract_is_a_leading_nul_byte(self):
        # Linux's abstract socket namespace (unix(7)): a sun_path starting
        # with a null byte names a socket outside the filesystem.
        assert UDSPort("\0kaede").abstract
        assert not UDSPort("/tmp/a.sock").abstract
        assert not UDSPort("").abstract
