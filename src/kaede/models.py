from typing import Optional, List, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from .tls.models import TLSConfig

@dataclass
class Limits:
    pass

@dataclass
class ClientLimits(Limits):
    max_connection_nums: int = 16384
    max_connection_keep: int = 65536 # The maximum number of connections stored for reconnection purposes (in HTTP/2, QUIC, etc.)
    max_connection_rate: List[Tuple[float, int]] = field(default_factory=lambda: [(1, 25), (5, 50), (60, 75)]) # [(period in sec, nums), ...]

    # Memory
    max_buffer_size: int = 10737418240 # in bytes

    # Timeout
    timeout_connection: float = 10
    timeout_handshake:  float = 5    # not TLS Handshake
    timeout_send:       float = 1800
    timeout_receive:    float = 900

@dataclass
class ServerLimits(Limits):
    max_connection_nums: int = 16384
    max_connection_keep: int = 65536 # The maximum number of connections stored for reconnection purposes (in HTTP/2, QUIC, etc.)
    max_connection_rate: List[Tuple[float, int]] = field(default_factory=lambda: [(1, 25), (5, 50), (60, 75)]) # [(period in sec, nums), ...]
    max_connection_history: int = 1024 # The floor for the per-host rate-limit history table size

    # Memory
    max_buffer_size: int = 20971520  # in bytes

    # Timeout
    timeout_connection: float = 10
    timeout_handshake:  float = 5    # not TLS Handshake
    timeout_send:       float = 1800
    timeout_receive:    float = 900
    timeout_callback:   float = 180

@dataclass
class Config:
    pass

@dataclass
class ClientConfig:
    tls:  Optional["TLSConfig"] = None
    alpn: Optional[List[str]] = None

@dataclass
class ServerConfig:
    tls:  Optional["TLSConfig"] = None
    alpn: Optional[List[str]] = None
