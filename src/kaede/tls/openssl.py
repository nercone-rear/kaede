import os
import sys
import glob
import time
import hmac
import ctypes
import hashlib
import ctypes.util
from ssl import CERT_NONE, CERT_REQUIRED
from typing import Optional, List, Dict

from .models import TLSVersion, TLSConfig
from .errors import TLSLibraryNotFoundError, TLSLibraryError, TLSConfigError, TLSHandshakeError, TLSVerificationError, TLSProtocolError, TLSClosedError, TLSECHError
from .helpers.ech import ECHConfigList, ECHStatus

VOID_P = ctypes.c_void_p

class Control:
    SET_MIN_PROTO_VERSION = 123
    SET_MAX_PROTO_VERSION = 124
    SET_GROUPS_LIST       = 92
    GET_NEGOTIATED_GROUP  = 134

    SET_TLSEXT_HOSTNAME      = 55
    SET_TLSEXT_SERVERNAME_CB = 53

    NAMETYPE_HOST = 0

    DTLS_GET_TIMEOUT      = 73
    DTLS_HANDLE_TIMEOUT   = 74
    DTLS_SET_LINK_MTU     = 120
    DTLS_GET_LINK_MIN_MTU = 121
    SET_MTU               = 17

    SET_MEM_EOF_RETURN    = 130

class Option:
    NO_COMPRESSION           = 0x00020000
    CIPHER_SERVER_PREFERENCE = 0x00400000
    NO_RENEGOTIATION         = 0x40000000

    NO_QUERY_MTU             = 0x00001000

class Verify:
    NONE = 0
    PEER = 1
    FAIL_IF_NO_PEER_CERT = 2

class Result:
    NONE             = 0
    SSL              = 1
    WANT_READ        = 2
    WANT_WRITE       = 3
    WANT_X509_LOOKUP = 4
    SYSCALL          = 5
    ZERO_RETURN      = 6

class Alert:
    OK          = 0
    ALERT_FATAL = 2
    NOACK       = 3

class Filetype:
    PEM  = 1
    ASN1 = 2

class Protocol:
    NUMBERS: Dict[TLSVersion, int] = {
        TLSVersion.TLSv1_0: 0x0301,
        TLSVersion.TLSv1_1: 0x0302,
        TLSVersion.TLSv1_2: 0x0303,
        TLSVersion.TLSv1_3: 0x0304
    }

    DATAGRAM_NUMBERS: Dict[TLSVersion, int] = {
        TLSVersion.TLSv1_0: 0xFEFF,
        TLSVersion.TLSv1_1: 0xFEFF,
        TLSVersion.TLSv1_2: 0xFEFD
    }

    @staticmethod
    def number(version: TLSVersion, datagram: bool = False) -> int:
        if not datagram:
            return Protocol.NUMBERS[version]

        if version not in Protocol.DATAGRAM_NUMBERS:
            raise TLSConfigError(f"DTLS has no counterpart to {version.value}. OpenSSL 3.6 and 4.0 support DTLS up to 1.2, so ask for TLS 1.2 or lower over a datagram transport.")

        return Protocol.DATAGRAM_NUMBERS[version]

class Timeval(ctypes.Structure):
    _fields_ = [("sec", ctypes.c_long), ("usec", ctypes.c_int if sys.platform.startswith("darwin") else ctypes.c_long)]

    @property
    def seconds(self) -> float:
        return self.sec + self.usec / 1000000.0

class Certificate:
    REASONS: Dict[int, str] = {
        10: "the certificate has expired",
        18: "the certificate is self signed",
        19: "the certificate chain ends in a self signed certificate",
        20: "the issuer certificate could not be found locally",
        62: "the certificate does not match the requested hostname"
    }

    @staticmethod
    def reason(code: int) -> str:
        return Certificate.REASONS.get(code, f"the certificate was rejected (code {code})")

class ALPN:
    @staticmethod
    def pack(names: List[str]) -> bytes:
        wire = b""

        for name in names:
            encoded = name.encode()

            if not 0 < len(encoded) < 256:
                raise TLSConfigError(f"The ALPN protocol name {name!r} must be between 1 and 255 bytes.")

            wire += bytes([len(encoded)]) + encoded

        return wire

    @staticmethod
    def unpack(wire: bytes) -> List[str]:
        names: List[str] = []
        offset = 0

        while offset < len(wire):
            length = wire[offset]

            if length == 0 or offset + 1 + length > len(wire):
                break

            names.append(wire[offset + 1:offset + 1 + length].decode(errors="replace"))
            offset += 1 + length

        return names

class Cookies:
    lifetime = 60.0

    def __init__(self, secret: Optional[bytes] = None):
        self.secret = secret or os.urandom(32)
        self.peer = ""

    def epoch(self, at: Optional[float] = None) -> int:
        return int((time.monotonic() if at is None else at) / self.lifetime)

    def sign(self, peer: str, epoch: int) -> bytes:
        return hmac.new(self.secret, f"{peer}|{epoch}".encode(), hashlib.sha256).digest()

    def make(self, peer: str, at: Optional[float] = None) -> bytes:
        return self.sign(peer, self.epoch(at))

    def check(self, peer: str, cookie: bytes, at: Optional[float] = None) -> bool:
        epoch = self.epoch(at)
        return any(hmac.compare_digest(cookie, self.sign(peer, window)) for window in (epoch, epoch - 1))

class OpenSSL:
    minimum_version = 0x30600000 # OpenSSL 3.6.0

    def __init__(self, *, ssl: Optional[ctypes.CDLL] = None, crypto: Optional[ctypes.CDLL] = None):
        self.ssl    = ssl or    OpenSSL.load_library("ssl")
        self.crypto = crypto or OpenSSL.load_library("crypto")

        self.configure()

    @staticmethod
    def load_library(name: str, required: bool = True) -> Optional[ctypes.CDLL]:
        for path in OpenSSL.candidate_paths(name):
            try:
                return ctypes.CDLL(path)
            except OSError:
                continue

        if required:
            raise TLSLibraryNotFoundError(f"Could not detect OpenSSL lib{name}. You can specify it using the KAEDE_OPENSSL/KAEDE_LIB{name.upper()} environ.")

    @staticmethod
    def candidate_paths(name: str) -> List[str]:
        paths: List[str] = []

        for path in [os.environ.get(f"KAEDE_LIB{name.upper()}", ""), os.environ.get("KAEDE_OPENSSL", "")]:
            if not path:
                continue

            if os.path.isdir(path):
                if sys.platform.startswith("darwin"):
                    paths.extend(sorted(glob.glob(os.path.join(path, f"lib{name}*.dylib")), reverse=True))

                elif sys.platform.startswith(("linux", "cygwin")):
                    paths.extend(sorted(glob.glob(os.path.join(path, f"lib{name}*.so*")), reverse=True))

            elif os.path.isfile(path):
                basename = os.path.basename(path)
                if f"lib{name}" in basename:
                    paths.append(path)

        if sys.platform.startswith("darwin"):
            patterns = [
                # OpenSSL 4.x
                f"/opt/homebrew/opt/openssl@4*/lib/lib{name}.dylib",
                f"/usr/local/opt/openssl@4*/lib/lib{name}.dylib",
                # OpenSSL 3.x
                f"/opt/homebrew/opt/openssl@3*/lib/lib{name}.dylib",
                f"/usr/local/opt/openssl@3*/lib/lib{name}.dylib",
                # Auto
                f"/opt/homebrew/lib/lib{name}.dylib",
                f"/usr/local/lib/lib{name}.dylib"
            ]
            for pattern in patterns:
                paths.extend(sorted(glob.glob(pattern), reverse=True))

        elif sys.platform.startswith(("linux", "cygwin")):
            patterns = [
                # OpenSSL 4.x
                f"/usr/lib/*/lib{name}.so.4",
                f"/usr/lib64/lib{name}.so.4",
                f"/usr/lib/lib{name}.so.4",
                f"/lib/*/lib{name}.so.4",
                f"/usr/local/lib/lib{name}.so.4",
                f"lib{name}.so.4",
                # OpenSSL 3.x
                f"/usr/lib/*/lib{name}.so.3",
                f"/usr/lib64/lib{name}.so.3",
                f"/usr/lib/lib{name}.so.3",
                f"/lib/*/lib{name}.so.3",
                f"/usr/local/lib/lib{name}.so.3",
                f"lib{name}.so.3",
                # Auto
                f"lib{name}.so"
            ]
            for pattern in patterns:
                paths.extend(sorted(glob.glob(pattern), reverse=True))

        found = ctypes.util.find_library(name)
        if found:
            paths.append(found)

        unique: List[str] = []

        for path in paths:
            if path not in unique:
                unique.append(path)

        return unique

    def bind(self, library: ctypes.CDLL, name: str, restype, argtypes: List, required: bool = True):
        function = getattr(library, name, None)

        if function is None:
            if required:
                raise TLSLibraryError(f"The OpenSSL library does not provide {name}. OpenSSL 3.6+ or 4.0+ is required.")

            return None

        function.restype = restype
        function.argtypes = argtypes

        return function

    def configure(self):
        VOID    = None
        INT     = ctypes.c_int
        UINT    = ctypes.c_uint
        LONG    = ctypes.c_long
        ULONG   = ctypes.c_ulong
        SIZE    = ctypes.c_size_t
        STR     = ctypes.c_char_p
        STR_P   = ctypes.POINTER(ctypes.c_char_p)
        UCHAR_P = ctypes.POINTER(ctypes.c_ubyte)
        UINT_P  = ctypes.POINTER(ctypes.c_uint)

        # Library
        self.version_num = self.bind(self.crypto, "OpenSSL_version_num", ULONG, [])
        self.version     = self.bind(self.crypto, "OpenSSL_version", STR, [INT])

        if self.version_num() < OpenSSL.minimum_version:
            raise TLSLibraryError(f"OpenSSL 3.6+ or 4.0+ is required, but found {self.version(0).decode()}.")

        # Errors
        self.error_get   = self.bind(self.crypto, "ERR_get_error", ULONG, [])
        self.error_clear = self.bind(self.crypto, "ERR_clear_error", VOID, [])
        self.error_text  = self.bind(self.crypto, "ERR_error_string_n", VOID, [ULONG, STR, SIZE])

        # Memory BIO
        self.bio_memory  = self.bind(self.crypto, "BIO_s_mem", VOID_P, [])

        # Memory BIO (DTLS)
        self.bio_dgram   = self.bind(self.crypto, "BIO_s_dgram_mem", VOID_P, [])
        self.bio_new     = self.bind(self.crypto, "BIO_new", VOID_P, [VOID_P])
        self.bio_free    = self.bind(self.crypto, "BIO_free", INT, [VOID_P])
        self.bio_write   = self.bind(self.crypto, "BIO_write", INT, [VOID_P, STR, INT])
        self.bio_read    = self.bind(self.crypto, "BIO_read", INT, [VOID_P, STR, INT])
        self.bio_pending = self.bind(self.crypto, "BIO_ctrl_pending", SIZE, [VOID_P])
        self.bio_control = self.bind(self.crypto, "BIO_ctrl", LONG, [VOID_P, INT, LONG, VOID_P])

        # Certificates
        self.x509_free  = self.bind(self.crypto, "X509_free", VOID, [VOID_P])
        self.x509_check = self.bind(self.crypto, "X509_check_host", INT, [VOID_P, STR, SIZE, UINT, STR_P])

        # Certificate store
        self.store       = self.bind(self.ssl, "SSL_CTX_get_cert_store", VOID_P, [VOID_P])
        self.store_add   = self.bind(self.crypto, "X509_STORE_add_cert", INT, [VOID_P, VOID_P])
        self.store_flags = self.bind(self.crypto, "X509_STORE_set_flags", INT, [VOID_P, ULONG])
        self.bio_buffer  = self.bind(self.crypto, "BIO_new_mem_buf", VOID_P, [VOID_P, INT])
        self.pem_x509    = self.bind(self.crypto, "PEM_read_bio_X509", VOID_P, [VOID_P, VOID_P, VOID_P, VOID_P])
        self.der_x509    = self.bind(self.crypto, "d2i_X509", VOID_P, [VOID_P, ctypes.POINTER(VOID_P), LONG])

        # Methods
        self.method        = self.bind(self.ssl, "TLS_method", VOID_P, [])
        self.method_client = self.bind(self.ssl, "TLS_client_method", VOID_P, [])
        self.method_server = self.bind(self.ssl, "TLS_server_method", VOID_P, [])

        # Methods (DTLS)
        self.method_datagram        = self.bind(self.ssl, "DTLS_method", VOID_P, [])
        self.method_datagram_client = self.bind(self.ssl, "DTLS_client_method", VOID_P, [])
        self.method_datagram_server = self.bind(self.ssl, "DTLS_server_method", VOID_P, [])

        # Context
        self.context_new          = self.bind(self.ssl, "SSL_CTX_new", VOID_P, [VOID_P])
        self.context_free         = self.bind(self.ssl, "SSL_CTX_free", VOID, [VOID_P])
        self.context_ctrl         = self.bind(self.ssl, "SSL_CTX_ctrl", LONG, [VOID_P, INT, LONG, VOID_P])
        self.context_callback     = self.bind(self.ssl, "SSL_CTX_callback_ctrl", LONG, [VOID_P, INT, VOID_P])
        self.context_options      = self.bind(self.ssl, "SSL_CTX_set_options", ULONG, [VOID_P, ULONG])
        self.context_verify       = self.bind(self.ssl, "SSL_CTX_set_verify", VOID, [VOID_P, INT, VOID_P])
        self.context_verify_depth = self.bind(self.ssl, "SSL_CTX_set_verify_depth", VOID, [VOID_P, INT])
        self.context_paths        = self.bind(self.ssl, "SSL_CTX_set_default_verify_paths", INT, [VOID_P])
        self.context_locations    = self.bind(self.ssl, "SSL_CTX_load_verify_locations", INT, [VOID_P, STR, STR])
        self.context_certificate  = self.bind(self.ssl, "SSL_CTX_use_certificate_chain_file", INT, [VOID_P, STR])
        self.context_key          = self.bind(self.ssl, "SSL_CTX_use_PrivateKey_file", INT, [VOID_P, STR, INT])
        self.context_key_check    = self.bind(self.ssl, "SSL_CTX_check_private_key", INT, [VOID_P])
        self.context_ciphers      = self.bind(self.ssl, "SSL_CTX_set_cipher_list", INT, [VOID_P, STR])
        self.context_ciphersuites = self.bind(self.ssl, "SSL_CTX_set_ciphersuites", INT, [VOID_P, STR])
        self.context_alpn         = self.bind(self.ssl, "SSL_CTX_set_alpn_protos", INT, [VOID_P, UCHAR_P, UINT])
        self.context_alpn_select  = self.bind(self.ssl, "SSL_CTX_set_alpn_select_cb", VOID, [VOID_P, VOID_P, VOID_P])

        # DTLS cookie exchange
        self.context_cookie_generate = self.bind(self.ssl, "SSL_CTX_set_cookie_generate_cb", VOID, [VOID_P, VOID_P])
        self.context_cookie_verify   = self.bind(self.ssl, "SSL_CTX_set_cookie_verify_cb", VOID, [VOID_P, VOID_P])
        self.listen                  = self.bind(self.ssl, "DTLSv1_listen", INT, [VOID_P, VOID_P])

        self.address_new  = self.bind(self.crypto, "BIO_ADDR_new", VOID_P, [])
        self.address_free = self.bind(self.crypto, "BIO_ADDR_free", VOID, [VOID_P])

        # Session
        self.new           = self.bind(self.ssl, "SSL_new", VOID_P, [VOID_P])
        self.free          = self.bind(self.ssl, "SSL_free", VOID, [VOID_P])
        self.ctrl          = self.bind(self.ssl, "SSL_ctrl", LONG, [VOID_P, INT, LONG, VOID_P])
        self.set_bio       = self.bind(self.ssl, "SSL_set_bio", VOID, [VOID_P, VOID_P, VOID_P])
        self.set_context   = self.bind(self.ssl, "SSL_set_SSL_CTX", VOID_P, [VOID_P, VOID_P])
        self.set_host      = self.bind(self.ssl, "SSL_set1_host", INT, [VOID_P, STR])
        self.connect_state = self.bind(self.ssl, "SSL_set_connect_state", VOID, [VOID_P])
        self.accept_state  = self.bind(self.ssl, "SSL_set_accept_state", VOID, [VOID_P])
        self.handshake     = self.bind(self.ssl, "SSL_do_handshake", INT, [VOID_P])
        self.read          = self.bind(self.ssl, "SSL_read", INT, [VOID_P, STR, INT])
        self.write         = self.bind(self.ssl, "SSL_write", INT, [VOID_P, STR, INT])
        self.shutdown      = self.bind(self.ssl, "SSL_shutdown", INT, [VOID_P])
        self.get_error     = self.bind(self.ssl, "SSL_get_error", INT, [VOID_P, INT])

        # Session (DTLS)
        self.data_mtu      = self.bind(self.ssl, "DTLS_get_data_mtu", SIZE, [VOID_P])

        # Session information
        self.get_version     = self.bind(self.ssl, "SSL_get_version", STR, [VOID_P])
        self.get_group       = self.bind(self.ssl, "SSL_get0_group_name", STR, [VOID_P])
        self.get_cipher      = self.bind(self.ssl, "SSL_get_current_cipher", VOID_P, [VOID_P])
        self.cipher_name     = self.bind(self.ssl, "SSL_CIPHER_get_name", STR, [VOID_P])
        self.get_verify      = self.bind(self.ssl, "SSL_get_verify_result", LONG, [VOID_P])
        self.get_certificate = self.bind(self.ssl, "SSL_get1_peer_certificate", VOID_P, [VOID_P])
        self.get_alpn        = self.bind(self.ssl, "SSL_get0_alpn_selected", VOID, [VOID_P, ctypes.POINTER(UCHAR_P), UINT_P])
        self.get_servername  = self.bind(self.ssl, "SSL_get_servername", STR, [VOID_P, INT])
        self.reused          = self.bind(self.ssl, "SSL_session_reused", INT, [VOID_P])

        # ECH (Encrypted Client Hello, RFC 9849). Only present from OpenSSL 4.0 onwards.
        self.echstore_new         = self.bind(self.ssl, "OSSL_ECHSTORE_new", VOID_P, [VOID_P, STR], required=False)
        self.echstore_free        = self.bind(self.ssl, "OSSL_ECHSTORE_free", VOID, [VOID_P], required=False)
        self.echstore_read_pem    = self.bind(self.ssl, "OSSL_ECHSTORE_read_pem", INT, [VOID_P, VOID_P, INT], required=False)
        self.context_set_echstore = self.bind(self.ssl, "SSL_CTX_set1_echstore", INT, [VOID_P, VOID_P], required=False)
        self.set_ech_config_list  = self.bind(self.ssl, "SSL_set1_ech_config_list", INT, [VOID_P, STR, SIZE], required=False)
        self.get_ech_status       = self.bind(self.ssl, "SSL_ech_get1_status", INT, [VOID_P, ctypes.POINTER(VOID_P), ctypes.POINTER(VOID_P)], required=False)
        self.get_ech_retry_config = self.bind(self.ssl, "SSL_ech_get1_retry_config", INT, [VOID_P, ctypes.POINTER(UCHAR_P), ctypes.POINTER(SIZE)], required=False)
        self.free_pointer         = self.bind(self.crypto, "CRYPTO_free", VOID, [VOID_P, STR, INT], required=False)

    def drain(self) -> List[str]:
        reasons: List[str] = []
        text = ctypes.create_string_buffer(512)

        while True:
            code = self.error_get()

            if not code:
                return reasons

            self.error_text(code, text, len(text))
            reasons.append(text.value.decode(errors="replace"))

    def reason(self, default: str = "unknown error") -> str:
        return "; ".join(self.drain()) or default

class TLSContext:
    def __init__(self, config: Optional[TLSConfig] = None, *, server: bool = False, alpn: Optional[List[str]] = None, datagram: bool = False, cookies: Optional[Cookies] = None, library: Optional[OpenSSL] = None):
        self.pointer = None
        self.callbacks: List = []

        self.config = config or TLSConfig()
        self.server = server
        self.alpn = alpn
        self.datagram = datagram
        self.cookies = cookies
        self.library = library or OpenSSL()

        self.build()

    def method(self):
        library = self.library

        if self.datagram:
            return library.method_datagram_server() if self.server else library.method_datagram_client()

        return library.method_server() if self.server else library.method_client()

    def build(self):
        library = self.library
        library.error_clear()

        self.pointer = library.context_new(self.method())

        if not self.pointer:
            raise TLSConfigError(f"Could not create the {'DTLS' if self.datagram else 'TLS'} context: {library.reason()}")

        library.context_ctrl(self.pointer, Control.SET_MIN_PROTO_VERSION, Protocol.number(self.config.minimum_version, self.datagram), None)

        options = Option.NO_COMPRESSION | Option.NO_RENEGOTIATION

        if self.datagram:
            options |= Option.NO_QUERY_MTU

        if self.server:
            options |= Option.CIPHER_SERVER_PREFERENCE

        library.context_options(self.pointer, options)

        self.apply_groups()
        self.apply_ciphers()
        self.apply_verification()
        self.apply_credentials()
        self.apply_ech()
        self.apply_alpn()
        self.apply_cookies()

    def apply_cookies(self):
        if self.cookies is None:
            return

        if not self.datagram or not self.server:
            raise TLSConfigError("Cookies belong to a DTLS server: they are how it makes a peer prove its address before it is served.")

        generating = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint))
        verifying  = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint)
        cookies = self.cookies

        def issue(session, cookie, length):
            value = cookies.make(cookies.peer)

            ctypes.memmove(cookie, value, len(value))
            length[0] = len(value)

            return 1

        def confirm(session, cookie, length):
            return 1 if cookies.check(cookies.peer, bytes(bytearray(cookie[:length]))) else 0

        issuing, confirming = generating(issue), verifying(confirm)
        self.callbacks.extend((issuing, confirming))

        self.library.context_cookie_generate(self.pointer, ctypes.cast(issuing, VOID_P))
        self.library.context_cookie_verify(self.pointer, ctypes.cast(confirming, VOID_P))

    def apply_groups(self):
        groups = ":".join(group.value for group in self.config.groups)

        if not groups:
            return

        if self.library.context_ctrl(self.pointer, Control.SET_GROUPS_LIST, 0, groups.encode()) != 1:
            raise TLSConfigError(f"OpenSSL rejected the group list {groups!r}: {self.library.reason()}")

    def apply_ciphers(self):
        suites  = ":".join(c.value for c in self.config.ciphers if c.value.startswith("TLS_"))
        ciphers = ":".join(c.value for c in self.config.ciphers if not c.value.startswith("TLS_"))

        if not suites and not ciphers:
            raise TLSConfigError("At least one cipher has to be configured.")

        if self.datagram:
            if not ciphers:
                raise TLSConfigError("Only TLS 1.3 cipher suites are configured, but DTLS 1.2 cannot use them. At least one TLS 1.2 cipher has to be configured for a datagram transport.")

            if self.library.context_ciphers(self.pointer, ciphers.encode()) != 1:
                raise TLSConfigError(f"OpenSSL rejected the cipher list {ciphers!r}: {self.library.reason()}")

            return

        if not suites and self.config.minimum_version == TLSVersion.TLSv1_3:
            raise TLSConfigError("The minimum version is TLS 1.3, but no TLS 1.3 cipher suite is configured.")

        if self.library.context_ciphersuites(self.pointer, suites.encode()) != 1:
            raise TLSConfigError(f"OpenSSL rejected the TLS 1.3 cipher suites {suites!r}: {self.library.reason()}")

        if not suites:
            self.library.context_ctrl(self.pointer, Control.SET_MAX_PROTO_VERSION, Protocol.number(TLSVersion.TLSv1_2), None)

        if ciphers:
            if self.library.context_ciphers(self.pointer, ciphers.encode()) != 1:
                raise TLSConfigError(f"OpenSSL rejected the cipher list {ciphers!r}: {self.library.reason()}")

        else:
            self.library.context_ctrl(self.pointer, Control.SET_MIN_PROTO_VERSION, Protocol.number(TLSVersion.TLSv1_3), None)

    def apply_verification(self):
        verify = self.config.verification(self.server)
        mode = Verify.NONE

        if verify != CERT_NONE:
            mode = Verify.PEER

            if self.server and verify == CERT_REQUIRED:
                mode |= Verify.FAIL_IF_NO_PEER_CERT

        self.library.context_verify(self.pointer, mode, None)

        if self.config.verify_flags:
            store = self.library.store(self.pointer)

            if not store or self.library.store_flags(store, int(self.config.verify_flags)) != 1:
                raise TLSConfigError(f"Could not apply the certificate verify flags: {self.library.reason()}")

        if self.config.cafile or self.config.capath:
            cafile = self.config.cafile.encode() if self.config.cafile else None
            capath = self.config.capath.encode() if self.config.capath else None

            if self.library.context_locations(self.pointer, cafile, capath) != 1:
                raise TLSConfigError(f"Could not load the CA certificates: {self.library.reason()}")

        if self.config.cadata is not None:
            self.apply_authorities()

        if not (self.config.cafile or self.config.capath or self.config.cadata is not None) and verify != CERT_NONE:
            if self.library.context_paths(self.pointer) != 1:
                raise TLSConfigError(f"Could not load the default CA certificates: {self.library.reason()}")

    def apply_authorities(self):
        store = self.library.store(self.pointer)

        if not store:
            raise TLSConfigError(f"Could not reach the certificate store: {self.library.reason()}")

        data = self.config.cadata
        loaded = 0

        if isinstance(data, str) or bytes(data).lstrip().startswith(b"-----"):
            raw = data.encode() if isinstance(data, str) else bytes(data)
            source = self.library.bio_buffer(raw, len(raw))

            if not source:
                raise TLSConfigError(f"Could not buffer the CA certificates: {self.library.reason()}")

            try:
                while True:
                    certificate = self.library.pem_x509(source, None, None, None)

                    if not certificate:
                        break

                    added = self.library.store_add(store, certificate)
                    self.library.x509_free(certificate)

                    if added != 1:
                        raise TLSConfigError(f"Could not trust a CA certificate: {self.library.reason()}")

                    loaded += 1

            finally:
                self.library.bio_free(source)

        else:
            raw = ctypes.create_string_buffer(bytes(data), len(data))
            cursor = VOID_P(ctypes.addressof(raw))
            end = ctypes.addressof(raw) + len(data)

            while cursor.value < end:
                certificate = self.library.der_x509(None, ctypes.byref(cursor), end - cursor.value)

                if not certificate:
                    if loaded:
                        raise TLSConfigError(f"The cadata carries {end - cursor.value} trailing bytes that are not a DER certificate: {self.library.reason()}")

                    break

                added = self.library.store_add(store, certificate)
                self.library.x509_free(certificate)

                if added != 1:
                    raise TLSConfigError(f"Could not trust a CA certificate: {self.library.reason()}")

                loaded += 1

        self.library.error_clear()

        if not loaded:
            raise TLSConfigError("The cadata does not contain any PEM or DER certificate.")

    def apply_credentials(self):
        if not self.config.certfile:
            return

        if self.library.context_certificate(self.pointer, self.config.certfile.encode()) != 1:
            raise TLSConfigError(f"Could not load the certificate {self.config.certfile!r}: {self.library.reason()}")

        keyfile = self.config.keyfile or self.config.certfile

        if self.library.context_key(self.pointer, keyfile.encode(), Filetype.PEM) != 1:
            raise TLSConfigError(f"Could not load the private key {keyfile!r}: {self.library.reason()}")

        if self.library.context_key_check(self.pointer) != 1:
            raise TLSConfigError(f"The private key {keyfile!r} does not match the certificate: {self.library.reason()}")

    def apply_ech(self):
        if not self.config.ech_pemfiles:
            return

        if not self.server:
            raise TLSConfigError("ech_pemfiles configures a TLS server: a client encrypts its Client Hello with the ECHConfigList passed to session(), not a PEM file.")

        if self.library.echstore_new is None:
            raise TLSConfigError("This OpenSSL does not provide ECH (Encrypted Client Hello): OpenSSL 4.0 or newer is required.")

        store = self.library.echstore_new(None, None)

        if not store:
            raise TLSConfigError(f"Could not create the ECH store: {self.library.reason()}")

        try:
            for path in self.config.ech_pemfiles:
                try:
                    with open(path, "rb") as file:
                        raw = file.read()

                except OSError as error:
                    raise TLSConfigError(f"Could not read the ECH configuration {path!r}: {error}")

                source = self.library.bio_buffer(raw, len(raw))

                if not source:
                    raise TLSConfigError(f"Could not buffer the ECH configuration {path!r}: {self.library.reason()}")

                try:
                    if self.library.echstore_read_pem(store, source, 1) != 1:
                        raise TLSConfigError(f"Could not load the ECH configuration {path!r}: {self.library.reason()}")

                finally:
                    self.library.bio_free(source)

            if self.library.context_set_echstore(self.pointer, store) != 1:
                raise TLSConfigError(f"Could not apply the ECH configuration to the context: {self.library.reason()}")

        finally:
            self.library.echstore_free(store)

    def apply_alpn(self):
        if not self.alpn:
            return

        if self.server:
            self.select_alpn()
            return

        wire = ALPN.pack(self.alpn)

        if self.library.context_alpn(self.pointer, ctypes.cast(ctypes.c_char_p(wire), ctypes.POINTER(ctypes.c_ubyte)), len(wire)) != 0:
            raise TLSConfigError(f"OpenSSL rejected the ALPN protocols {self.alpn}: {self.library.reason()}")

    def select_alpn(self):
        signature = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint, VOID_P)
        preference = list(self.alpn)

        def choose(session, out, outlen, incoming, length, argument):
            offered = bytes(bytearray(incoming[:length]))
            positions: Dict[str, tuple] = {}
            offset = 0

            while offset < len(offered):
                size = offered[offset]

                if size == 0 or offset + 1 + size > len(offered):
                    break

                positions.setdefault(offered[offset + 1:offset + 1 + size].decode(errors="replace"), (offset + 1, size))
                offset += 1 + size

            for name in preference:
                if name in positions:
                    start, size = positions[name]

                    out[0] = ctypes.cast(ctypes.addressof(incoming.contents) + start, ctypes.POINTER(ctypes.c_ubyte))
                    outlen[0] = size
                    return Alert.OK

            return Alert.ALERT_FATAL

        callback = signature(choose)
        self.callbacks.append(callback)

        self.library.context_alpn_select(self.pointer, ctypes.cast(callback, VOID_P), None)

    def session(self, *, hostname: Optional[str] = None, ech: Optional[bytes] = None) -> "TLSSession":
        return TLSSession(self, hostname=hostname, ech=ech)

    def memory(self):
        return self.library.bio_dgram() if self.datagram else self.library.bio_memory()

    def free(self):
        if self.pointer:
            self.library.context_free(self.pointer)
            self.pointer = None

    def __del__(self):
        self.free()

class TLSSession:
    link_mtu = 1280

    def __init__(self, context: TLSContext, *, hostname: Optional[str] = None, ech: Optional[bytes] = None):
        self.pointer = None
        self.address = None

        self.context = context
        self.library = context.library
        self.server = context.server
        self.datagram = context.datagram
        self.hostname = hostname

        if ech is not None:
            ECHConfigList.parse(ech) # validate the wire format before handing it to OpenSSL

        self.ech = ech

        self.established = False
        self.closed = False
        self.ended = False
        self.truncated = False

        self.pointer = self.library.new(context.pointer)

        if not self.pointer:
            raise TLSHandshakeError(f"Could not create the TLS session: {self.library.reason()}")

        self.incoming = self.library.bio_new(context.memory())
        self.outgoing = self.library.bio_new(context.memory())
        self.library.set_bio(self.pointer, self.incoming, self.outgoing)
        self.mtu(TLSSession.link_mtu)

        if self.server:
            self.library.accept_state(self.pointer)
        else:
            self.prepare()
            self.library.connect_state(self.pointer)

    @staticmethod
    def identity(host: str) -> bytes:
        try:
            return host.encode("ascii")
        except UnicodeEncodeError:
            try:
                return host.encode("idna")
            except UnicodeError as error:
                raise TLSConfigError(f"The hostname {host!r} is not a valid internationalized domain name: {error}")

    def prepare(self):
        verify = self.context.config.verification(self.server)
        host = self.hostname

        if not host:
            if verify != CERT_NONE:
                raise TLSConfigError("A verifying TLS client needs a hostname to check the certificate against. Pass a hostname, or set verify_mode to CERT_NONE to connect without checking identity.")

        else:
            if host.endswith("."):
                host = host[:-1]

            identity = TLSSession.identity(host)

            if not host.replace(".", "").isdigit() and ":" not in host:
                self.library.ctrl(self.pointer, Control.SET_TLSEXT_HOSTNAME, Control.NAMETYPE_HOST, ctypes.cast(ctypes.c_char_p(identity), VOID_P))

            if verify != CERT_NONE:
                self.library.set_host(self.pointer, identity)

        if self.ech is not None:
            self.apply_ech()

    def apply_ech(self):
        if self.library.set_ech_config_list is None:
            raise TLSConfigError("This OpenSSL does not provide ECH (Encrypted Client Hello): OpenSSL 4.0 or newer is required.")

        if self.library.set_ech_config_list(self.pointer, self.ech, len(self.ech)) != 1:
            raise TLSConfigError(f"OpenSSL rejected the ECH configuration: {self.library.reason()}")

    def feed(self, data: bytes):
        if not data:
            return

        written = self.library.bio_write(self.incoming, data, len(data))

        if written != len(data):
            raise TLSProtocolError(f"Only {written} of {len(data)} bytes could be buffered: {self.library.reason()}")

    def packets(self) -> List[bytes]:
        chunks: List[bytes] = []

        while True:
            pending = self.library.bio_pending(self.outgoing)

            if not pending:
                return chunks

            buffer = ctypes.create_string_buffer(pending)
            read = self.library.bio_read(self.outgoing, buffer, pending)

            if read <= 0:
                return chunks

            chunks.append(buffer.raw[:read])

    def drain(self) -> bytes:
        return b"".join(self.packets())

    def timeout(self) -> Optional[float]:
        if not self.datagram:
            return None

        remaining = Timeval()

        if self.library.ctrl(self.pointer, Control.DTLS_GET_TIMEOUT, 0, ctypes.byref(remaining)) != 1:
            return None

        return max(0.0, remaining.seconds)

    def expire(self) -> bool:
        if not self.datagram:
            return False

        return self.library.ctrl(self.pointer, Control.DTLS_HANDLE_TIMEOUT, 0, None) > 0

    def mtu(self, value: int):
        if self.datagram:
            self.library.ctrl(self.pointer, Control.DTLS_SET_LINK_MTU, value, None)

    def limit(self) -> Optional[int]:
        if not self.datagram or not self.established:
            return None

        return self.library.data_mtu(self.pointer) or None

    def listen(self, peer: str) -> bool:
        if not self.datagram or self.context.cookies is None:
            return True

        if self.address is None:
            self.address = self.library.address_new()

        self.context.cookies.peer = peer
        self.library.error_clear()

        return self.library.listen(self.pointer, self.address) > 0

    def handshake(self) -> bool:
        if self.established:
            return True

        self.library.error_clear()
        code = self.library.handshake(self.pointer)

        if code == 1:
            self.established = True
            return True

        result = self.library.get_error(self.pointer, code)

        if result in (Result.WANT_READ, Result.WANT_WRITE):
            return False

        self.fail("The TLS handshake failed")

    def eof(self):
        self.ended = True
        self.library.bio_control(self.incoming, Control.SET_MEM_EOF_RETURN, 0, None)

    def read(self, n: int = 16384) -> bytes:
        buffer = ctypes.create_string_buffer(n)

        self.library.error_clear()
        code = self.library.read(self.pointer, buffer, n)

        if code > 0:
            return buffer.raw[:code]

        result = self.library.get_error(self.pointer, code)

        if result == Result.ZERO_RETURN:
            self.closed = True
            return b""

        if result in (Result.WANT_READ, Result.WANT_WRITE):
            return b""

        if self.ended:
            self.closed = True
            self.truncated = True
            return b""

        self.fail("The TLS session could not be read")

    def write(self, data: bytes) -> int:
        if self.closed:
            raise TLSClosedError("This TLS session is already closed.")

        if not data:
            return 0

        self.library.error_clear()
        code = self.library.write(self.pointer, data, len(data))

        if code > 0:
            return code

        result = self.library.get_error(self.pointer, code)

        if result in (Result.WANT_READ, Result.WANT_WRITE):
            return 0

        self.fail("The TLS session could not be written to")

    def unwrap(self):
        if self.closed or not self.pointer:
            return

        self.library.error_clear()
        self.library.shutdown(self.pointer)
        self.closed = True

    def fail(self, message: str):
        if self.ech is not None:
            status = self.ech_status

            if status is not None and status.code in (ECHStatus.FAILED_ECH, ECHStatus.FAILED_ECH_BAD_NAME):
                raise TLSECHError(f"{message}: the server rejected Encrypted Client Hello ({self.library.reason()})", status=status, retry_config=self.ech_retry_config)

        code = self.library.get_verify(self.pointer)
        reason = self.library.reason()

        if code != 0:
            raise TLSVerificationError(f"{message}: {Certificate.reason(code)} ({reason})", code)

        raise TLSHandshakeError(f"{message}: {reason}")

    @property
    def version(self) -> Optional[str]:
        if not self.pointer:
            return None

        value = self.library.get_version(self.pointer)
        return value.decode() if value else None

    @property
    def cipher(self) -> Optional[str]:
        if not self.pointer:
            return None

        current = self.library.get_cipher(self.pointer)

        if not current:
            return None

        value = self.library.cipher_name(current)
        return value.decode() if value else None

    @property
    def group(self) -> Optional[str]:
        if not self.pointer:
            return None

        value = self.library.get_group(self.pointer)
        return value.decode() if value else None

    @property
    def protocol(self) -> Optional[str]:
        if not self.pointer:
            return None

        data = ctypes.POINTER(ctypes.c_ubyte)()
        length = ctypes.c_uint(0)

        self.library.get_alpn(self.pointer, ctypes.byref(data), ctypes.byref(length))

        if not length.value or not data:
            return None

        return bytes(bytearray(data[:length.value])).decode(errors="replace")

    @property
    def servername(self) -> Optional[str]:
        if not self.pointer:
            return None

        value = self.library.get_servername(self.pointer, Control.NAMETYPE_HOST)
        return value.decode() if value else None

    @property
    def verified(self) -> bool:
        return bool(self.pointer) and self.library.get_verify(self.pointer) == 0

    @property
    def reused(self) -> bool:
        return bool(self.pointer) and bool(self.library.reused(self.pointer))

    @property
    def ech_status(self) -> Optional[ECHStatus]:
        if not self.pointer or self.ech is None or self.library.get_ech_status is None:
            return None

        inner = VOID_P()
        outer = VOID_P()
        code = self.library.get_ech_status(self.pointer, ctypes.byref(inner), ctypes.byref(outer))

        inner_sni = ctypes.cast(inner, ctypes.c_char_p).value.decode() if inner else None
        outer_sni = ctypes.cast(outer, ctypes.c_char_p).value.decode() if outer else None

        if inner:
            self.library.free_pointer(inner, None, 0)

        if outer:
            self.library.free_pointer(outer, None, 0)

        return ECHStatus(code=code, inner_sni=inner_sni, outer_sni=outer_sni)

    @property
    def ech_retry_config(self) -> Optional[bytes]:
        if not self.pointer or self.ech is None or self.library.get_ech_retry_config is None:
            return None

        data = ctypes.POINTER(ctypes.c_ubyte)()
        length = ctypes.c_size_t(0)

        if self.library.get_ech_retry_config(self.pointer, ctypes.byref(data), ctypes.byref(length)) != 1 or not length.value:
            return None

        raw = bytes(bytearray(data[:length.value]))
        self.library.free_pointer(data, None, 0)

        return raw

    def free(self):
        if self.pointer:
            self.library.free(self.pointer)
            self.pointer = None

        if self.address:
            self.library.address_free(self.address)
            self.address = None

    def __del__(self):
        self.free()
