import pickle

import pytest

from kaede.tcp import TCPPort
from kaede.udp import UDPPort

# RFC 9293 (TCP) and RFC 768 (UDP) both define the port field as a 16-bit
# unsigned integer, so the valid range is exactly 0-65535.

PORTS = [TCPPort, UDPPort]

@pytest.mark.parametrize("port", PORTS)
class TestRange:
    @pytest.mark.parametrize("value", [0, 1, 80, 443, 1023, 1024, 49151, 49152, 65534, 65535])
    def test_accepts_whole_16bit_range(self, port, value):
        assert port(value) == value

    @pytest.mark.parametrize("value", [-1, -65535, 65536, 65537, 131070])
    def test_rejects_out_of_range(self, port, value):
        with pytest.raises(ValueError):
            port(value)

    @pytest.mark.parametrize("value", ["80", 80.0, None, b"80", [80]])
    def test_rejects_non_integer(self, port, value):
        with pytest.raises(TypeError):
            port(value)

    def test_rejects_bool(self, port):
        # bool is a subclass of int, but True/False are not port numbers.
        with pytest.raises(TypeError):
            port(True)

    def test_defaults_to_zero(self, port):
        assert port() == 0

@pytest.mark.parametrize("port", PORTS)
class TestBehaviour:
    def test_is_an_int(self, port):
        assert isinstance(port(80), int)
        assert isinstance(port(80), port)

    def test_compares_and_hashes_as_int(self, port):
        assert port(443) == 443
        assert hash(port(443)) == hash(443)
        assert {port(443): "https"}[443] == "https"

    def test_survives_pickling(self, port):
        assert pickle.loads(pickle.dumps(port(8080))) == port(8080)

    def test_repr_names_the_type(self, port):
        assert repr(port(80)) == f"{port.__name__}(80)"

    def test_dynamic_is_only_port_zero(self, port):
        # RFC 6335: port 0 is reserved and is used to request an OS-assigned port.
        assert port(0).dynamic
        assert not port(1).dynamic
        assert not port(65535).dynamic

    def test_privileged_is_the_system_range(self, port):
        # RFC 6335: 1-1023 are the System (privileged) Ports.
        assert port(1).privileged
        assert port(80).privileged
        assert port(1023).privileged
        assert not port(1024).privileged
        assert not port(0).privileged

def test_tcp_and_udp_ports_are_distinct_types():
    assert not isinstance(TCPPort(80), UDPPort)
    assert not isinstance(UDPPort(80), TCPPort)
