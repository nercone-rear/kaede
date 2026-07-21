from typing import List
from dataclasses import dataclass, field

from ...models import Limits, Config
from ..models import HTTPVersion

@dataclass
class HTTPLimits(Limits):
    max_message_size: int = 1073741824    # in bytes, The total size of the HTTP message allowed for reception.
    max_message_offload_size: int = 98304 # in bytes, The total size of an HTTP message that can be held in memory.

    max_message_body_size: int = 1073741824    # in bytes, The size of the HTTP message body allowed for reception.
    max_message_body_offload_size: int = 65536 # in bytes, The size of the HTTP message body that can be held in memory.

    max_startline_size: int = 8192  # in bytes, the request/status line ceiling
    max_headers_size:   int = 65536 # in bytes, the whole header (or trailer) block
    max_header_count:   int = 128   # the number of header fields allowed in one block
    max_chunk_ext_size: int = 4096  # in bytes, one chunk size line with its extensions

    decompress_chunk_size: int = 65536

    ws_linger_timeout: float = 5

@dataclass
class HTTPConfig(Config):
    versions: List[HTTPVersion] = field(default_factory=lambda: ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"])
