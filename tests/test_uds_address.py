import pickle
import sys

import pytest

from kaede.uds import UDSAddress

# POSIX defines the UDS bind path through struct sockaddr_un.sun_path, whose
# size is platform dependent (104 bytes on BSD/Darwin, 108 on Linux) and always
# reserves at least one byte for the implementation's null terminator.

class TestValidation:
    def test_accepts_a_path(self):
        assert UDSAddress("/tmp/kaede.sock") == "/tmp/kaede.sock"

    def test_defaults_to_empty(self):
        assert UDSAddress() == ""

    def test_accepts_the_longest_permitted_path(self):
        value = "/" + "a" * (UDSAddress.limit - 1)
        assert len(value.encode()) == UDSAddress.limit
        assert UDSAddress(value) == value

    def test_rejects_a_path_beyond_the_limit(self):
        value = "/" + "a" * UDSAddress.limit

        with pytest.raises(ValueError):
            UDSAddress(value)

    @pytest.mark.parametrize("value", [None, 80, 80.0, b"/tmp/kaede.sock", ["/tmp/kaede.sock"]])
    def test_rejects_non_string(self, value):
        with pytest.raises(TypeError):
            UDSAddress(value)

    def test_the_limit_matches_the_current_platform(self):
        assert UDSAddress.limit == (103 if sys.platform == "darwin" else 107)

class TestBehaviour:
    def test_is_a_string(self):
        assert isinstance(UDSAddress("/tmp/a.sock"), str)

    def test_compares_and_hashes_as_a_string(self):
        assert UDSAddress("/tmp/a.sock") == "/tmp/a.sock"
        assert hash(UDSAddress("/tmp/a.sock")) == hash("/tmp/a.sock")
        assert {UDSAddress("/tmp/a.sock"): "yes"}["/tmp/a.sock"] == "yes"

    def test_survives_pickling(self):
        assert pickle.loads(pickle.dumps(UDSAddress("/tmp/a.sock"))) == UDSAddress("/tmp/a.sock")

    def test_repr_names_the_type(self):
        assert repr(UDSAddress("/tmp/a.sock")) == "UDSAddress('/tmp/a.sock')"

    def test_dynamic_is_only_the_empty_address(self):
        assert UDSAddress("").dynamic
        assert not UDSAddress("/tmp/a.sock").dynamic

    def test_abstract_is_a_leading_nul_byte(self):
        # Linux's abstract socket namespace (unix(7)): a sun_path starting
        # with a null byte names a socket outside the filesystem.
        assert UDSAddress("\0kaede").abstract
        assert not UDSAddress("/tmp/a.sock").abstract
        assert not UDSAddress("").abstract
