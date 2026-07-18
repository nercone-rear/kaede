import importlib

import pytest

# Modules that carry an implementation must be importable. Protocols that are
# still unimplemented (quic, and the http/dns layers that depend on it) are
# intentionally absent from this list.
MODULES = [
    "kaede",
    "kaede.ip",
    "kaede.url",
    "kaede.constants",
    "kaede.protocol",
    "kaede.tls",
    "kaede.tls.models",
    "kaede.tls.errors",
    "kaede.tls.openssl",
    "kaede.tcp",
    "kaede.tcp.models",
    "kaede.tcp.errors",
    "kaede.tcp.protocol",
    "kaede.tcp.api.client",
    "kaede.tcp.api.server",
    "kaede.udp",
    "kaede.udp.models",
    "kaede.udp.protocol",
    "kaede.udp.api.server",
    "kaede.uds",
    "kaede.uds.models",
    "kaede.uds.errors",
    "kaede.uds.protocol",
    "kaede.uds.api.client",
    "kaede.uds.api.server",
    "kaede.http",
    "kaede.http.models",
    "kaede.http.headers",
    "kaede.http.errors",
    "kaede.http.responses",
]

@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name):
    importlib.import_module(name)

@pytest.mark.parametrize("name", MODULES)
def test_exports_resolve(name):
    module = importlib.import_module(name)

    for export in getattr(module, "__all__", []):
        assert hasattr(module, export), f"{name}.__all__ lists {export!r}, which does not exist"

def test_server_limits_are_not_shared_between_instances():
    from kaede.protocol import ServerLimits

    first, second = ServerLimits(), ServerLimits()
    first.max_connection_rate.append((3600, 1000))

    assert second.max_connection_rate != first.max_connection_rate
