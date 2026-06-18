import ssl
import pytest
from kaede.tls.models import (
    TLSInfo,
    TLSServerConfig,
    TLSClientConfig,
    Group,
    Cipher,
    VERSION_MAP,
    GROUP_MAP,
    CIPHER_MAP,
)


class TestTLSInfo:
    def test_version_field(self):
        info = TLSInfo(version="TLSv1.3", group=None, cipher=None)
        assert info.version == "TLSv1.3"

    def test_group_none(self):
        info = TLSInfo(version="TLSv1.3", group=None, cipher=None)
        assert info.group is None

    def test_cipher_none(self):
        info = TLSInfo(version="TLSv1.3", group=None, cipher=None)
        assert info.cipher is None

    def test_all_fields_set(self):
        info = TLSInfo(version="TLSv1.3", group=Group.X25519, cipher=Cipher.TLS_AES_128_GCM_SHA256)
        assert info.version == "TLSv1.3"
        assert info.group == Group.X25519
        assert info.cipher == Cipher.TLS_AES_128_GCM_SHA256

    def test_version_tls12(self):
        info = TLSInfo(version="TLSv1.2", group=None, cipher=None)
        assert info.version == "TLSv1.2"

    def test_group_prime256v1(self):
        info = TLSInfo(version=None, group=Group.prime256v1, cipher=None)
        assert info.group == Group.prime256v1


class TestTLSServerConfig:
    def test_certfile_default_none(self):
        assert TLSServerConfig().certfile is None

    def test_keyfile_default_none(self):
        assert TLSServerConfig().keyfile is None

    def test_cafile_default_none(self):
        assert TLSServerConfig().cafile is None

    def test_default_verify_mode(self):
        assert TLSServerConfig().verify_mode == ssl.CERT_REQUIRED

    def test_default_minimum_version(self):
        assert TLSServerConfig().minimum_version == ssl.TLSVersion.TLSv1_2

    def test_default_ciphers_not_empty(self):
        ciphers = TLSServerConfig().ciphers
        assert len(ciphers) > 0

    def test_default_groups_not_empty(self):
        groups = TLSServerConfig().groups
        assert len(groups) > 0

    def test_default_ciphers_contain_tls13(self):
        ciphers = TLSServerConfig().ciphers
        assert Cipher.TLS_AES_128_GCM_SHA256 in ciphers

    def test_default_groups_contain_x25519(self):
        groups = TLSServerConfig().groups
        assert Group.X25519 in groups

    def test_custom_certfile(self):
        cfg = TLSServerConfig(certfile="/path/to/cert.pem")
        assert cfg.certfile == "/path/to/cert.pem"

    def test_custom_keyfile(self):
        cfg = TLSServerConfig(keyfile="/path/to/key.pem")
        assert cfg.keyfile == "/path/to/key.pem"

    def test_custom_ciphers(self):
        ciphers = [Cipher.TLS_AES_256_GCM_SHA384]
        cfg = TLSServerConfig(ciphers=ciphers)
        assert cfg.ciphers == ciphers


class TestTLSClientConfig:
    def test_verify_default_true(self):
        assert TLSClientConfig().verify is True

    def test_check_hostname_default_true(self):
        assert TLSClientConfig().check_hostname is True

    def test_cafile_default_none(self):
        assert TLSClientConfig().cafile is None

    def test_capath_default_none(self):
        assert TLSClientConfig().capath is None

    def test_certfile_default_none(self):
        assert TLSClientConfig().certfile is None

    def test_keyfile_default_none(self):
        assert TLSClientConfig().keyfile is None

    def test_default_minimum_version(self):
        assert TLSClientConfig().minimum_version == ssl.TLSVersion.TLSv1_2

    def test_default_ciphers_not_empty(self):
        assert len(TLSClientConfig().ciphers) > 0

    def test_default_groups_not_empty(self):
        assert len(TLSClientConfig().groups) > 0

    def test_default_ciphers_contain_tls13(self):
        assert Cipher.TLS_AES_128_GCM_SHA256 in TLSClientConfig().ciphers

    def test_default_groups_contain_x25519(self):
        assert Group.X25519 in TLSClientConfig().groups

    def test_custom_verify_false(self):
        cfg = TLSClientConfig(verify=False)
        assert cfg.verify is False

    def test_custom_check_hostname_false(self):
        cfg = TLSClientConfig(check_hostname=False)
        assert cfg.check_hostname is False

    def test_custom_cafile(self):
        cfg = TLSClientConfig(cafile="/etc/ssl/ca.pem")
        assert cfg.cafile == "/etc/ssl/ca.pem"


class TestGroupEnum:
    def test_x25519_value(self):
        assert Group.X25519.value == "x25519"

    def test_prime256v1_value(self):
        assert Group.prime256v1.value == "prime256v1"

    def test_secp384r1_value(self):
        assert Group.secp384r1.value == "secp384r1"

    def test_secp521r1_value(self):
        assert Group.secp521r1.value == "secp521r1"

    def test_x25519mlkem768_value(self):
        assert Group.X25519MLKEM768.value == "X25519MLKEM768"

    def test_ffdhe2048_value(self):
        assert Group.FFDHE2048.value == "ffdhe2048"

    def test_mlkem768_value(self):
        assert Group.MLKEM768.value == "MLKEM768"


class TestCipherEnum:
    def test_tls13_aes128_value(self):
        assert Cipher.TLS_AES_128_GCM_SHA256.value == "TLS_AES_128_GCM_SHA256"

    def test_tls13_aes256_value(self):
        assert Cipher.TLS_AES_256_GCM_SHA384.value == "TLS_AES_256_GCM_SHA384"

    def test_tls13_chacha_value(self):
        assert Cipher.TLS_CHACHA20_POLY1305_SHA256.value == "TLS_CHACHA20_POLY1305_SHA256"

    def test_ecdhe_rsa_aes128(self):
        assert Cipher.ECDHE_RSA_AES128_GCM_SHA256.value == "ECDHE-RSA-AES128-GCM-SHA256"

    def test_ecdhe_ecdsa_aes256(self):
        assert Cipher.ECDHE_ECDSA_AES256_GCM_SHA384.value == "ECDHE-ECDSA-AES256-GCM-SHA384"


class TestVersionMap:
    def test_contains_tls13(self):
        assert "TLSv1.3" in VERSION_MAP.values()

    def test_contains_tls12(self):
        assert "TLSv1.2" in VERSION_MAP.values()

    def test_contains_tls11(self):
        assert "TLSv1.1" in VERSION_MAP.values()

    def test_contains_tls10(self):
        assert "TLSv1.0" in VERSION_MAP.values()

    def test_tlsv1_maps_to_tls10(self):
        assert VERSION_MAP.get("TLSv1") == "TLSv1.0"

    def test_tlsv13_maps_to_tls13(self):
        assert VERSION_MAP.get("TLSv1.3") == "TLSv1.3"


class TestGroupMap:
    def test_x25519_lookup(self):
        assert GROUP_MAP.get("x25519") == Group.X25519

    def test_x25519_case_variant(self):
        assert GROUP_MAP.get("X25519") == Group.X25519

    def test_prime256v1_lookup(self):
        assert GROUP_MAP.get("prime256v1") == Group.prime256v1

    def test_secp256r1_alias(self):
        assert GROUP_MAP.get("secp256r1") == Group.prime256v1

    def test_p256_alias(self):
        assert GROUP_MAP.get("P-256") == Group.prime256v1

    def test_secp384r1_lookup(self):
        assert GROUP_MAP.get("secp384r1") == Group.secp384r1

    def test_mlkem768_lookup(self):
        assert GROUP_MAP.get("MLKEM768") == Group.MLKEM768

    def test_ffdhe2048_lookup(self):
        assert GROUP_MAP.get("ffdhe2048") == Group.FFDHE2048

    def test_unknown_key_returns_none(self):
        assert GROUP_MAP.get("unknown-group") is None


class TestCipherMap:
    def test_aes128_gcm_lookup(self):
        assert CIPHER_MAP.get("AES128-GCM-SHA256") == Cipher.AES128_GCM_SHA256

    def test_aes256_gcm_lookup(self):
        assert CIPHER_MAP.get("AES256-GCM-SHA384") == Cipher.AES256_GCM_SHA384

    def test_tls13_cipher_lookup(self):
        assert CIPHER_MAP.get("TLS_AES_128_GCM_SHA256") == Cipher.TLS_AES_128_GCM_SHA256

    def test_ecdhe_rsa_lookup(self):
        assert CIPHER_MAP.get("ECDHE-RSA-AES128-GCM-SHA256") == Cipher.ECDHE_RSA_AES128_GCM_SHA256

    def test_unknown_cipher_returns_none(self):
        assert CIPHER_MAP.get("UNKNOWN-CIPHER") is None

    def test_map_not_empty(self):
        assert len(CIPHER_MAP) > 0
