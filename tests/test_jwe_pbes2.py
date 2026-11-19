import json

import pytest

from jose import jwe
from jose.backends.pbes2_backend import DEFAULT_P2C, DEFAULT_P2S_NUM_BYTES, PBES2Key
from jose.constants import ALGORITHMS
from jose.exceptions import JWEError, JWEParseError, JWKError
from jose.utils import base64url_decode, base64url_encode

try:
    import jose.backends.cryptography_backend  # noqa: F401

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

try:
    from jwcrypto import jwe as jwcrypto_jwe
    from jwcrypto import jwk as jwcrypto_jwk

    JWCRYPTO_AVAILABLE = True
except ImportError:
    JWCRYPTO_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not CRYPTOGRAPHY_AVAILABLE, reason="PBES2 key management requires the cryptography backend"
)

PASSWORD = "correct horse battery staple"
PLAINTEXT = b"Live long and prosper."

# A stable "legacy" ciphertext produced by an independent implementation
# (jwcrypto) with the small iteration count of 100 that older tokens use.
LEGACY_P2C_100_TOKEN = (
    "eyJhbGciOiAiUEJFUzItSFMyNTYrQTEyOEtXIiwgImVuYyI6ICJBMTI4R0NNIiwgInAyYyI6IDEwMCwgInAycyI6ICJNREV5"
    "TXpRMU5qYzRPV0ZpWTJSbFpnIn0.DZaUv_5bsRBzo9ldIcBSYTBGthJEJ6Gm.ZqT1THaODPf5Vyn1.iKp6S5qKgPSWIajY"
    "mQUh_1rPVofL2w.01DSku4_xH6v79xCQwUx2Q"
)

PBES2_ALGS = tuple(sorted(ALGORITHMS.PBES2_KW))


def _jwcrypto_password_key(password=PASSWORD):
    return jwcrypto_jwk.JWK(kty="oct", k=base64url_encode(password.encode("utf-8")).decode("ascii"))


def _jwcrypto_encrypt(alg, enc, plaintext=PLAINTEXT, password=PASSWORD, p2c=None, p2s=None):
    protected = {"alg": alg, "enc": enc}
    if p2c is not None:
        protected["p2c"] = p2c
    if p2s is not None:
        protected["p2s"] = p2s
    token = jwcrypto_jwe.JWE(
        plaintext=plaintext,
        protected=json.dumps(protected),
        recipient=_jwcrypto_password_key(password),
    )
    return token.serialize(compact=True)


def _reheader(token, header):
    segments = token.split(b".")
    return b".".join([base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))] + segments[1:])


class TestPbes2RoundTrip:
    @pytest.mark.parametrize("alg", PBES2_ALGS)
    @pytest.mark.parametrize("enc", [ALGORITHMS.A128GCM, ALGORITHMS.A256CBC_HS512])
    def test_encrypt_decrypt_round_trip(self, alg, enc):
        token = jwe.encrypt(PLAINTEXT, PASSWORD, algorithm=alg, encryption=enc)
        assert jwe.decrypt(token, PASSWORD) == PLAINTEXT

    @pytest.mark.parametrize("alg", PBES2_ALGS)
    def test_p2s_p2c_are_negotiated_into_the_header(self, alg):
        token = jwe.encrypt(PLAINTEXT, PASSWORD, algorithm=alg, encryption=ALGORITHMS.A128GCM)
        header = jwe.get_unverified_header(token)
        assert isinstance(header["p2c"], int)
        assert header["p2c"] == DEFAULT_P2C
        salt = base64url_decode(header["p2s"].encode("ascii"))
        assert len(salt) == DEFAULT_P2S_NUM_BYTES

    def test_each_encryption_uses_a_fresh_salt(self):
        first = jwe.get_unverified_header(jwe.encrypt(PLAINTEXT, PASSWORD, algorithm=ALGORITHMS.PBES2_HS256_A128KW))
        second = jwe.get_unverified_header(jwe.encrypt(PLAINTEXT, PASSWORD, algorithm=ALGORITHMS.PBES2_HS256_A128KW))
        assert first["p2s"] != second["p2s"]

    def test_bytes_password_and_oct_jwk_are_accepted(self):
        raw_key = base64url_encode(b"0123456789abcdef").decode("ascii")
        token = jwe.encrypt(
            PLAINTEXT,
            {"kty": "oct", "k": raw_key},
            algorithm=ALGORITHMS.PBES2_HS256_A128KW,
        )
        assert jwe.decrypt(token, b"0123456789abcdef") == PLAINTEXT
        assert jwe.decrypt(token, {"kty": "oct", "k": raw_key}) == PLAINTEXT

    def test_invalid_key_material_is_rejected(self):
        key = PBES2Key(PASSWORD, ALGORITHMS.PBES2_HS256_A128KW)
        with pytest.raises(JWKError):
            PBES2Key(12345, ALGORITHMS.PBES2_HS256_A128KW)
        with pytest.raises(JWKError):
            PBES2Key(PASSWORD, ALGORITHMS.A128KW)
        with pytest.raises(JWKError):
            PBES2Key({"kty": "RSA"}, ALGORITHMS.PBES2_HS256_A128KW)
        assert key.prepared_key == PASSWORD.encode("utf-8")

    def test_pbes2_algorithms_are_whitelisted_as_supported(self):
        for alg in PBES2_ALGS:
            assert alg in ALGORITHMS.SUPPORTED


class TestPbes2HeaderValidation:
    def _token(self, alg=ALGORITHMS.PBES2_HS256_A128KW, enc=ALGORITHMS.A128GCM):
        return jwe.encrypt(PLAINTEXT, PASSWORD, algorithm=alg, encryption=enc)

    def test_missing_p2s_is_rejected(self):
        token = self._token()
        header = jwe.get_unverified_header(token)
        del header["p2s"]
        with pytest.raises(JWEParseError, match='must include a "p2s"'):
            jwe.decrypt(_reheader(token, header), PASSWORD)

    def test_missing_p2c_is_rejected(self):
        token = self._token()
        header = jwe.get_unverified_header(token)
        del header["p2c"]
        with pytest.raises(JWEParseError, match='must include a "p2c"'):
            jwe.decrypt(_reheader(token, header), PASSWORD)

    @pytest.mark.parametrize("bad_p2c", [0, -1, "8192", 8.192, True, None])
    def test_invalid_p2c_is_rejected(self, bad_p2c):
        token = self._token()
        header = jwe.get_unverified_header(token)
        header["p2c"] = bad_p2c
        with pytest.raises(JWEParseError, match='Invalid PBES2 "p2c"'):
            jwe.decrypt(_reheader(token, header), PASSWORD)

    def test_short_salt_is_rejected(self):
        token = self._token()
        header = jwe.get_unverified_header(token)
        header["p2s"] = base64url_encode(b"short").decode("ascii")
        with pytest.raises(JWEParseError, match="salt must be at least 8 octets"):
            jwe.decrypt(_reheader(token, header), PASSWORD)

    def test_non_string_salt_is_rejected(self):
        token = self._token()
        header = jwe.get_unverified_header(token)
        header["p2s"] = 1234
        with pytest.raises(JWEParseError, match='Invalid PBES2 "p2s"'):
            jwe.decrypt(_reheader(token, header), PASSWORD)

    def test_wrong_password_fails_authentication(self):
        token = self._token()
        with pytest.raises(JWEError):
            jwe.decrypt(token, "the wrong password")

    def test_prepare_pbes2_params_validates_inputs(self):
        key = PBES2Key(PASSWORD, ALGORITHMS.PBES2_HS256_A128KW)
        with pytest.raises(JWKError):
            key.prepare_pbes2_params(p2c=0)
        with pytest.raises(JWKError):
            key.prepare_pbes2_params(p2c="1000")
        with pytest.raises(JWKError):
            key.prepare_pbes2_params(p2s=b"short")
        params = key.prepare_pbes2_params(p2s=b"0123456789abcdef", p2c=4096)
        assert params["p2c"] == 4096
        assert base64url_decode(params["p2s"].encode("ascii")) == b"0123456789abcdef"

    def test_prepare_accepts_base64url_salt_string(self):
        key = PBES2Key(PASSWORD, ALGORITHMS.PBES2_HS256_A128KW)
        params = key.prepare_pbes2_params(p2s=base64url_encode(b"0123456789abcdef").decode("ascii"), p2c=4096)
        assert base64url_decode(params["p2s"].encode("ascii")) == b"0123456789abcdef"

    def test_malformed_base64url_salt_is_rejected_at_key_level(self):
        key = PBES2Key(PASSWORD, ALGORITHMS.PBES2_HS256_A128KW)
        with pytest.raises(JWKError):
            key.prepare_pbes2_params(p2s=1234)
        # A payload whose decoded salt is shorter than 8 octets is invalid.
        with pytest.raises(JWKError, match="at least 8 octets"):
            key.prepare_pbes2_params(p2s=base64url_encode(b"short").decode("ascii"))

    def test_derive_without_negotiated_params_fails(self):
        key = PBES2Key(PASSWORD, ALGORITHMS.PBES2_HS256_A128KW)
        with pytest.raises(JWKError, match="p2s and p2c"):
            key.wrap_key(b"sixteen byte key")
        with pytest.raises(JWKError, match="p2s and p2c"):
            key._derive_kek()
        with pytest.raises(JWKError, match="p2s and p2c"):
            key.unwrap_key(b"wrapped")

    def test_non_ascii_base64url_salt_is_rejected_at_key_level(self):
        key = PBES2Key(PASSWORD, ALGORITHMS.PBES2_HS256_A128KW)
        with pytest.raises(JWKError, match="Invalid PBES2 p2s"):
            key._validate_p2s("not-ascii-\u00e9")

    def test_wrap_key_accepts_inline_params_and_to_dict_round_trips(self):
        key = PBES2Key(PASSWORD, ALGORITHMS.PBES2_HS256_A128KW)
        wrapped = key.wrap_key(b"sixteen byte key", p2s=b"0123456789abcdef", p2c=4096)
        rebuilt = PBES2Key(key.to_dict(), ALGORITHMS.PBES2_HS256_A128KW)
        cek = rebuilt.unwrap_key(wrapped, base64url_encode(b"0123456789abcdef").decode("ascii"), 4096)
        assert cek == b"sixteen byte key"

    def test_unwrapping_garbage_raises_jwk_error(self):
        key = PBES2Key(PASSWORD, ALGORITHMS.PBES2_HS256_A128KW)
        with pytest.raises(JWKError):
            key.unwrap_key(b"not a wrapped key" * 4, base64url_encode(b"0123456789abcdef").decode("ascii"), 4096)


class TestLegacyCiphertext:
    def test_legacy_small_p2c_token_still_decrypts(self):
        header = jwe.get_unverified_header(LEGACY_P2C_100_TOKEN)
        assert header["p2c"] == 100
        assert jwe.decrypt(LEGACY_P2C_100_TOKEN, PASSWORD) == PLAINTEXT

    @pytest.mark.parametrize("legacy_p2c", [1, 7, 100, 1000])
    @pytest.mark.skipif(not JWCRYPTO_AVAILABLE, reason="jwcrypto is required to mint legacy tokens")
    def test_legacy_iteration_counts_remain_supported(self, legacy_p2c):
        token = _jwcrypto_encrypt(
            ALGORITHMS.PBES2_HS256_A128KW,
            ALGORITHMS.A128GCM,
            p2c=legacy_p2c,
            p2s=base64url_encode(b"0123456789abcdef").decode("ascii"),
        )
        assert jwe.decrypt(token, PASSWORD) == PLAINTEXT


@pytest.mark.skipif(not JWCRYPTO_AVAILABLE, reason="jwcrypto is required for cross-implementation tests")
class TestJwcryptoInterop:
    @pytest.mark.parametrize("alg", PBES2_ALGS)
    @pytest.mark.parametrize("enc", [ALGORITHMS.A128GCM, ALGORITHMS.A256CBC_HS512])
    def test_jose_encrypt_jwcrypto_decrypt(self, alg, enc):
        token = jwe.encrypt(PLAINTEXT, PASSWORD, algorithm=alg, encryption=enc)
        foreign = jwcrypto_jwe.JWE()
        foreign.deserialize(token.decode("ascii"))
        foreign.decrypt(_jwcrypto_password_key())
        assert foreign.plaintext == PLAINTEXT

    @pytest.mark.parametrize("alg", PBES2_ALGS)
    @pytest.mark.parametrize("enc", [ALGORITHMS.A128GCM, ALGORITHMS.A256CBC_HS512])
    def test_jwcrypto_encrypt_jose_decrypt(self, alg, enc):
        token = _jwcrypto_encrypt(alg, enc)
        assert jwe.decrypt(token, PASSWORD) == PLAINTEXT

    @pytest.mark.parametrize("alg", PBES2_ALGS)
    def test_jwcrypto_default_negotiation_is_understood(self, alg):
        # Let jwcrypto pick p2s/p2c itself and confirm jose honours the header.
        token = _jwcrypto_encrypt(alg, ALGORITHMS.A128GCM)
        header = jwe.get_unverified_header(token)
        assert "p2s" in header and "p2c" in header
        assert jwe.decrypt(token, PASSWORD) == PLAINTEXT
