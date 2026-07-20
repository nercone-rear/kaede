import socket
import ctypes
from typing import Optional, List, Tuple

from ..tls.models import TLSConfig
from ..tls.openssl import VOID_P, OpenSSL, TLSContext, Timeval, Option
from ..tls.errors import TLSConfigError, TLSHandshakeError

class Stream:
    # SSL_new_stream
    UNI      = 1 << 0
    NO_BLOCK = 1 << 1
    ADVANCE  = 1 << 2

    # SSL_accept_stream
    ACCEPT_NO_BLOCK = 1 << 0
    ACCEPT_UNI      = 1 << 1
    ACCEPT_BIDI     = 1 << 2

    # SSL_set_default_stream_mode
    MODE_NONE      = 0
    MODE_AUTO_BIDI = 1
    MODE_AUTO_UNI  = 2

    # SSL_get_stream_read_state / SSL_get_stream_write_state
    STATE_NONE         = 0
    STATE_OK           = 1
    STATE_WRONG_DIR    = 2
    STATE_FINISHED     = 3
    STATE_RESET_LOCAL  = 4
    STATE_RESET_REMOTE = 5
    STATE_CONN_CLOSED  = 6

    # SSL_get_stream_type
    TYPE_NONE  = 0
    TYPE_READ  = 1 << 0
    TYPE_WRITE = 1 << 1
    TYPE_BIDI  = TYPE_READ | TYPE_WRITE

class Incoming:
    AUTO   = 0
    ACCEPT = 1
    REJECT = 2

class Listener:
    NO_VALIDATE     = 1 << 1
    ACCEPT_NO_BLOCK = 1 << 0

class Shutdown:
    RAPID           = 1 << 0
    NO_STREAM_FLUSH = 1 << 1
    NO_BLOCK        = 1 << 2
    WAIT_PEER       = 1 << 3

class Close:
    LOCAL     = 1 << 0
    TRANSPORT = 1 << 1

class Capability:
    HANDLES_SRC  = 1 << 0
    HANDLES_DST  = 1 << 1
    PROVIDES_SRC = 1 << 2
    PROVIDES_DST = 1 << 3

    ALL = HANDLES_SRC | HANDLES_DST | PROVIDES_SRC | PROVIDES_DST

    SET_LOCAL_ENABLE = 84
    GET_EFFECTIVE    = 85
    GET              = 86
    SET              = 87

class BIOMessage(ctypes.Structure):
    _fields_ = [
        ("data",   VOID_P),
        ("length", ctypes.c_size_t),
        ("peer",   VOID_P),
        ("local",  VOID_P),
        ("flags",  ctypes.c_uint64)
    ]

class ShutdownArgs(ctypes.Structure):
    _fields_ = [
        ("code",   ctypes.c_uint64),
        ("reason", ctypes.c_char_p)
    ]

class ResetArgs(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint64)
    ]

class CloseInfo(ctypes.Structure):
    _fields_ = [
        ("code",   ctypes.c_uint64),
        ("frame",  ctypes.c_uint64),
        ("reason", ctypes.c_char_p),
        ("length", ctypes.c_size_t),
        ("flags",  ctypes.c_uint32)
    ]

class QTLS:
    def __init__(self, library: Optional[OpenSSL] = None):
        self.library = library or OpenSSL()
        self.configure()

    def bind(self, library, name: str, restype, argtypes: List, required: bool = True):
        return self.library.bind(library, name, restype, argtypes, required)

    def configure(self):
        INT     = ctypes.c_int
        UINT32  = ctypes.c_uint32
        UINT64  = ctypes.c_uint64
        USHORT  = ctypes.c_ushort
        SIZE    = ctypes.c_size_t
        SIZE_P  = ctypes.POINTER(ctypes.c_size_t)
        INT_P   = ctypes.POINTER(ctypes.c_int)
        UINT64_P = ctypes.POINTER(ctypes.c_uint64)
        TIMEVAL_P = ctypes.POINTER(Timeval)
        MESSAGE_P = ctypes.POINTER(BIOMessage)

        ssl, crypto = self.library.ssl, self.library.crypto

        # Methods
        self.client_method = self.bind(ssl, "OSSL_QUIC_client_method", VOID_P, [])
        self.server_method = self.bind(ssl, "OSSL_QUIC_server_method", VOID_P, [])

        # Connections
        self.set_blocking     = self.bind(ssl, "SSL_set_blocking_mode", INT, [VOID_P, INT])
        self.events           = self.bind(ssl, "SSL_handle_events", INT, [VOID_P])
        self.event_timeout    = self.bind(ssl, "SSL_get_event_timeout", INT, [VOID_P, TIMEVAL_P, INT_P])
        self.set_peer_address = self.bind(ssl, "SSL_set1_initial_peer_addr", INT, [VOID_P, VOID_P])
        self.is_connection    = self.bind(ssl, "SSL_is_connection", INT, [VOID_P])
        self.get_connection   = self.bind(ssl, "SSL_get0_connection", VOID_P, [VOID_P])
        self.established      = self.bind(ssl, "SSL_is_init_finished", INT, [VOID_P])

        # Listeners
        self.new_listener      = self.bind(ssl, "SSL_new_listener", VOID_P, [VOID_P, UINT64])
        self.listen            = self.bind(ssl, "SSL_listen", INT, [VOID_P])
        self.accept_connection = self.bind(ssl, "SSL_accept_connection", VOID_P, [VOID_P, UINT64])
        self.pending_connections = self.bind(ssl, "SSL_get_accept_connection_queue_len", SIZE, [VOID_P])

        # Streams
        self.default_stream_mode = self.bind(ssl, "SSL_set_default_stream_mode", INT, [VOID_P, UINT32])
        self.incoming_streams    = self.bind(ssl, "SSL_set_incoming_stream_policy", INT, [VOID_P, INT, UINT64])
        self.new_stream          = self.bind(ssl, "SSL_new_stream", VOID_P, [VOID_P, UINT64])
        self.accept_stream       = self.bind(ssl, "SSL_accept_stream", VOID_P, [VOID_P, UINT64])
        self.pending_streams     = self.bind(ssl, "SSL_get_accept_stream_queue_len", SIZE, [VOID_P])
        self.stream_id           = self.bind(ssl, "SSL_get_stream_id", UINT64, [VOID_P])
        self.stream_type         = self.bind(ssl, "SSL_get_stream_type", INT, [VOID_P])
        self.stream_local        = self.bind(ssl, "SSL_is_stream_local", INT, [VOID_P])
        self.read_state          = self.bind(ssl, "SSL_get_stream_read_state", INT, [VOID_P])
        self.write_state         = self.bind(ssl, "SSL_get_stream_write_state", INT, [VOID_P])
        self.read_code           = self.bind(ssl, "SSL_get_stream_read_error_code", INT, [VOID_P, UINT64_P])
        self.write_code          = self.bind(ssl, "SSL_get_stream_write_error_code", INT, [VOID_P, UINT64_P])
        self.conclude            = self.bind(ssl, "SSL_stream_conclude", INT, [VOID_P, UINT64])
        self.reset               = self.bind(ssl, "SSL_stream_reset", INT, [VOID_P, VOID_P, SIZE])

        # Closing
        self.shutdown   = self.bind(ssl, "SSL_shutdown_ex", INT, [VOID_P, UINT64, ctypes.POINTER(ShutdownArgs), SIZE])
        self.close_info = self.bind(ssl, "SSL_get_conn_close_info", INT, [VOID_P, ctypes.POINTER(CloseInfo), SIZE])
        self.peer_address = self.bind(ssl, "SSL_get_peer_addr", INT, [VOID_P, VOID_P], required=False) # OpenSSL 4.0+ only

        # Datagram BIOs
        self.pair     = self.bind(crypto, "BIO_new_bio_dgram_pair", INT, [ctypes.POINTER(VOID_P), SIZE, ctypes.POINTER(VOID_P), SIZE])
        self.send     = self.bind(crypto, "BIO_sendmmsg", INT, [VOID_P, MESSAGE_P, SIZE, SIZE, UINT64, SIZE_P])
        self.receive  = self.bind(crypto, "BIO_recvmmsg", INT, [VOID_P, MESSAGE_P, SIZE, SIZE, UINT64, SIZE_P])
        self.bio_ctrl = self.bind(crypto, "BIO_ctrl", ctypes.c_long, [VOID_P, INT, ctypes.c_long, VOID_P])
        self.up_ref   = self.bind(crypto, "BIO_up_ref", INT, [VOID_P])

        # Addresses
        self.address_make   = self.bind(crypto, "BIO_ADDR_rawmake", INT, [VOID_P, INT, VOID_P, SIZE, USHORT])
        self.address_family = self.bind(crypto, "BIO_ADDR_family", INT, [VOID_P])
        self.address_raw    = self.bind(crypto, "BIO_ADDR_rawaddress", INT, [VOID_P, VOID_P, SIZE_P])
        self.address_port   = self.bind(crypto, "BIO_ADDR_rawport", USHORT, [VOID_P])

    @property
    def available(self) -> bool:
        return self.client_method is not None

    @property
    def servable(self) -> bool:
        return self.available and self.peer_address is not None

    def address(self, host: str, port: int):
        address = self.library.address_new()

        if not address:
            raise TLSConfigError(f"Could not allocate an address: {self.library.reason()}")

        try:
            self.remake(address, host, port)
        except BaseException:
            self.library.address_free(address)
            raise

        return address

    def remake(self, address, host: str, port: int):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        packed = socket.inet_pton(family, host)
        buffer = ctypes.create_string_buffer(packed, len(packed))

        if self.address_make(address, family, ctypes.cast(buffer, VOID_P), len(packed), socket.htons(port)) != 1:
            raise TLSConfigError(f"OpenSSL rejected the address {host}:{port}: {self.library.reason()}")

    def where(self, address) -> Tuple[str, int]:
        if not address:
            return ("", 0)

        family = self.address_family(address)

        if family not in (socket.AF_INET, socket.AF_INET6):
            return ("", 0)

        buffer = ctypes.create_string_buffer(16)
        length = ctypes.c_size_t(len(buffer))

        if self.address_raw(address, ctypes.cast(buffer, VOID_P), ctypes.byref(length)) != 1:
            return ("", 0)

        return (socket.inet_ntop(family, buffer.raw[:length.value]), socket.ntohs(self.address_port(address)))

class QUICPair:
    def __init__(self, qtls: QTLS):
        self.qtls = qtls
        self.library = qtls.library

        inner, outer = VOID_P(), VOID_P()

        if qtls.pair(ctypes.byref(inner), 0, ctypes.byref(outer), 0) != 1:
            raise TLSConfigError(f"Could not create the QUIC datagram BIOs: {self.library.reason()}")

        self.inner = inner
        self.outer = outer

        self.source = self.library.address_new()
        self.target = self.library.address_new()

        self.prepare()

    def prepare(self):
        for half in (self.inner, self.outer):
            self.qtls.bio_ctrl(half, Capability.SET, Capability.ALL, None)

        for half in (self.inner, self.outer):
            if self.qtls.bio_ctrl(half, Capability.SET_LOCAL_ENABLE, 1, None) != 1:
                raise TLSConfigError(f"The QUIC datagram BIOs would not carry local addresses: {self.library.reason()}")

    def feed(self, data: bytes, peer, local) -> bool:
        if not data:
            return False

        buffer = ctypes.create_string_buffer(data, len(data))
        message = BIOMessage(ctypes.cast(buffer, VOID_P), len(data), local, peer, 0)
        done = ctypes.c_size_t(0)

        self.library.error_clear()

        return self.qtls.send(self.outer, ctypes.byref(message), ctypes.sizeof(BIOMessage), 1, 0, ctypes.byref(done)) == 1 and done.value == 1

    def packets(self, limit: int = 65535) -> List[Tuple[bytes, Tuple[str, int]]]:
        chunks: List[Tuple[bytes, Tuple[str, int]]] = []

        while True:
            buffer = ctypes.create_string_buffer(limit)
            message = BIOMessage(ctypes.cast(buffer, VOID_P), limit, self.source, self.target, 0)
            done = ctypes.c_size_t(0)

            self.library.error_clear()

            if self.qtls.receive(self.outer, ctypes.byref(message), ctypes.sizeof(BIOMessage), 1, 0, ctypes.byref(done)) != 1 or not done.value:
                return chunks

            chunks.append((buffer.raw[:message.length], self.qtls.where(self.target)))

    def free(self):
        for name in ("source", "target"):
            address = getattr(self, name)

            if address:
                self.library.address_free(address)
                setattr(self, name, None)

        for name in ("inner", "outer"):
            half = getattr(self, name)

            if half:
                self.library.bio_free(half)
                setattr(self, name, None)

    def __del__(self):
        self.free()

class QUICContext(TLSContext):
    def __init__(self, config: Optional[TLSConfig] = None, *, server: bool = False, alpn: Optional[List[str]] = None, qtls: Optional[QTLS] = None, library: Optional[OpenSSL] = None):
        self.qtls = qtls or QTLS(library)

        if not self.qtls.available:
            raise TLSConfigError("This OpenSSL was built without QUIC support.")

        super().__init__(config, server=server, alpn=alpn, datagram=False, cookies=None, library=self.qtls.library)

    def method(self):
        if not self.server:
            return self.qtls.client_method()

        if self.qtls.server_method is None:
            raise TLSConfigError("This OpenSSL does not provide a QUIC server method.")

        return self.qtls.server_method()

    def build(self):
        library = self.library
        library.error_clear()

        self.pointer = library.context_new(self.method())

        if not self.pointer:
            raise TLSConfigError(f"Could not create the QUIC context: {library.reason()}")

        library.context_options(self.pointer, Option.NO_COMPRESSION | Option.NO_RENEGOTIATION)

        self.apply_groups()
        self.apply_ciphers()
        self.apply_verification()
        self.apply_credentials()
        self.apply_ech()
        self.apply_alpn()

    def apply_ciphers(self):
        suites = ":".join(c.value for c in self.config.ciphers if c.value.startswith("TLS_"))

        if not suites:
            raise TLSConfigError("QUIC uses TLS 1.3 only, but no TLS 1.3 cipher suite is configured.")

        if self.library.context_ciphersuites(self.pointer, suites.encode()) != 1:
            raise TLSConfigError(f"OpenSSL rejected the TLS 1.3 cipher suites {suites!r}: {self.library.reason()}")

    def apply_alpn(self):
        if not self.alpn:
            raise TLSConfigError("QUIC requires ALPN, but no protocol was offered.")

        super().apply_alpn()

    def session(self, *, hostname: Optional[str] = None):
        raise TLSConfigError("A QUIC context does not make TLS sessions. Use connection() or listener().")

    def connection(self):
        self.library.error_clear()
        pointer = self.library.new(self.pointer)

        if not pointer:
            raise TLSHandshakeError(f"Could not create the QUIC connection: {self.library.reason()}")

        return pointer

    def listener(self, *, validate: bool = True):
        self.library.error_clear()
        pointer = self.qtls.new_listener(self.pointer, 0 if validate else Listener.NO_VALIDATE)

        if not pointer:
            raise TLSHandshakeError(f"Could not create the QUIC listener: {self.library.reason()}")

        return pointer
