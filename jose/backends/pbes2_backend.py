from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

from ..constants import ALGORITHMS
from ..exceptions import JWKError
from ..utils import base64url_decode, base64url_encode, ensure_binary
from . import get_random_bytes
from .base import Key

#: Default PBES2 iteration count used when the caller does not provide "p2c".
#: RFC 7518 Section 4.8.1.2 recommends a minimum of 1000 iterations; 8192 is
#: the value chosen by most JOSE implementations (e.g. jwcrypto, Nimbus).
DEFAULT_P2C = 8192

#: PBES2 salt input ("p2s") MUST contain at least 8 octets of randomness
#: (RFC 7518 Section 4.8.1.1). 128 bits matches the other implementations.
DEFAULT_P2S_NUM_BYTES = 16


class PBES2Key(Key):
    """Password-based key for the PBES2-HS*+A*KW JWE key management algorithms.

    The password supplied by the caller is turned into an AES key-encryption-key
    with PBKDF2 using the salt ("p2s") and iteration count ("p2c") carried in
    the JWE protected header. The derived KEK then performs standard AES key
    wrapping of the content encryption key (RFC 7518, Section 4.8).
    """

    HASH_ALGS = {
        ALGORITHMS.PBES2_HS256_A128KW: (hashes.SHA256, 16),
        ALGORITHMS.PBES2_HS384_A192KW: (hashes.SHA384, 24),
        ALGORITHMS.PBES2_HS512_A256KW: (hashes.SHA512, 32),
    }

    def __init__(self, key, algorithm):
        if algorithm not in ALGORITHMS.PBES2_KW:
            raise JWKError("%s is not a valid PBES2 algorithm" % algorithm)

        self._algorithm = algorithm
        self._hash_alg, self._kek_size = self.HASH_ALGS[algorithm]

        if isinstance(key, dict):
            key = self._process_jwk(key)
        elif isinstance(key, str):
            key = key.encode("utf-8")
        elif not isinstance(key, (bytes, bytearray)):
            raise JWKError("PBES2 key must be a string, bytes or an 'oct' JWK")

        self.prepared_key = ensure_binary(key)
        self._p2s = None
        self._p2c = None

    def _process_jwk(self, jwk_dict):
        if jwk_dict.get("kty") != "oct":
            raise JWKError("Incorrect key type. Expected: 'oct', Received: %s" % jwk_dict.get("kty"))
        return base64url_decode(ensure_binary(jwk_dict["k"]))

    def to_dict(self):
        return {
            "alg": self._algorithm,
            "kty": "oct",
            "k": base64url_encode(self.prepared_key),
        }

    def prepare_pbes2_params(self, p2s=None, p2c=None):
        """Negotiate the PBES2 "p2s"/"p2c" header parameters for encryption.

        Generates a fresh random salt and applies the default iteration count
        when the caller does not pin them, then stashes the negotiated values
        on this key so :meth:`wrap_key` derives the KEK from the same values
        that are emitted in the protected header.

        Returns:
            dict: Header entries ("p2s" as base64url str, "p2c" as int).
        """
        if p2s is None:
            p2s = get_random_bytes(DEFAULT_P2S_NUM_BYTES)
        else:
            p2s = self._validate_p2s(p2s)

        if p2c is None:
            p2c = DEFAULT_P2C
        else:
            p2c = self._validate_p2c(p2c)

        self._p2s = p2s
        self._p2c = p2c
        return {"p2s": base64url_encode(p2s).decode("ascii"), "p2c": p2c}

    @staticmethod
    def _validate_p2s(p2s):
        if isinstance(p2s, str):
            try:
                p2s = base64url_decode(p2s.encode("ascii"))
            except Exception as e:
                raise JWKError("Invalid PBES2 p2s header parameter: %s" % e)
        elif not isinstance(p2s, (bytes, bytearray)):
            raise JWKError("Invalid PBES2 p2s header parameter: must be bytes or a base64url string")
        # RFC 7518 4.8.1.1: the salt input MUST be at least 8 octets.
        if len(p2s) < 8:
            raise JWKError("Invalid PBES2 p2s header parameter: salt must be at least 8 octets")
        return ensure_binary(p2s)

    @staticmethod
    def _validate_p2c(p2c):
        # bool is a subclass of int, but True/False are not valid counts.
        if isinstance(p2c, bool) or not isinstance(p2c, int):
            raise JWKError("Invalid PBES2 p2c header parameter: iteration count must be an integer")
        if p2c < 1:
            raise JWKError("Invalid PBES2 p2c header parameter: iteration count must be a positive integer")
        return p2c

    def _derive_kek(self, p2s=None, p2c=None):
        if p2s is None:
            p2s = self._p2s
        if p2c is None:
            p2c = self._p2c
        if p2s is None or p2c is None:
            raise JWKError("PBES2 p2s and p2c header parameters are required")

        # RFC 7518 4.8.1.1: salt = UTF8(alg) || 0x00 || p2s
        salt = self._algorithm.encode("utf-8") + b"\x00" + p2s
        kdf = PBKDF2HMAC(
            algorithm=self._hash_alg(),
            length=self._kek_size,
            salt=salt,
            iterations=p2c,
            backend=default_backend(),
        )
        return kdf.derive(self.prepared_key)

    def wrap_key(self, key_data, p2s=None, p2c=None):
        if p2s is not None or p2c is not None:
            self._p2s = self._validate_p2s(p2s) if p2s is not None else self._p2s
            self._p2c = self._validate_p2c(p2c) if p2c is not None else self._p2c
        kek = self._derive_kek()
        return aes_key_wrap(kek, ensure_binary(key_data), default_backend())

    def unwrap_key(self, wrapped_key, p2s=None, p2c=None):
        if p2s is None or p2c is None:
            raise JWKError("PBES2 p2s and p2c header parameters are required")
        p2s = self._validate_p2s(p2s)
        p2c = self._validate_p2c(p2c)
        kek = self._derive_kek(p2s, p2c)
        try:
            return aes_key_unwrap(kek, ensure_binary(wrapped_key), default_backend())
        except InvalidUnwrap as cause:
            raise JWKError(cause)
