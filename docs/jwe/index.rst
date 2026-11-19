JSON Web Encryption
===================

JSON Web Encryption (JWE) are used to encrypt a payload and represent it as a
compact URL-safe string.

Supported Content Encryption Algorithms
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following algorithms are currently supported.

+------------------+------------------------------------------------+
| Encryption Value | Encryption Algorithm, Mode, and Auth Tag       |
+==================+================================================+
| A128CBC-HS256    | AES w/128 bit key in CBC mode w/SHA256 HMAC    |
+------------------+------------------------------------------------+
| A192CBC-HS384    | AES w/128 bit key in CBC mode w/SHA256 HMAC    |
+------------------+------------------------------------------------+
| A256CBC-HS512    | AES w/128 bit key in CBC mode w/SHA256 HMAC    |
+------------------+------------------------------------------------+
| A128GCM          | AES w/128 bit key in GCM mode and GCM auth tag |
+------------------+------------------------------------------------+
| A192GCM          | AES w/192 bit key in GCM mode and GCM auth tag |
+------------------+------------------------------------------------+
| A256GCM          | AES w/256 bit key in GCM mode and GCM auth tag |
+------------------+------------------------------------------------+

Supported Key Management Algorithms
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following algorithms are currently supported.

+-----------------+------------------------------------------------+
| Algorithm Value | Key Wrap Algorithm                             |
+=================+================================================+
| DIR             | Direct (no key wrap)                           |
+-----------------+------------------------------------------------+
| RSA1-5          | RSAES with PKCS1 v1.5                          |
+-----------------+------------------------------------------------+
| RSA-OAEP        | RSAES OAEP using default parameters            |
+-----------------+------------------------------------------------+
| RSA-OAEP-256    | RSAES OAEP using SHA-256 and MGF1 with SHA-256 |
+-----------------+------------------------------------------------+
| A128KW          | AES Key Wrap with default IV using 128-bit key |
+-----------------+------------------------------------------------+
| A192KW   m      | AES Key Wrap with default IV using 192-bit key |
+-----------------+------------------------------------------------+
| A256KW          | AES Key Wrap with default IV using 256-bit key |
+-----------------+------------------------------------------------+
| PBES2-HS256+A128KW | PBES2 with HMAC SHA-256 and A128KW wrapping  |
+-----------------+------------------------------------------------+
| PBES2-HS384+A192KW | PBES2 with HMAC SHA-384 and A192KW wrapping  |
+-----------------+------------------------------------------------+
| PBES2-HS512+A256KW | PBES2 with HMAC SHA-512 and A256KW wrapping  |
+-----------------+------------------------------------------------+

Examples
^^^^^^^^

Encrypting Payloads
-------------------

.. code:: python

        >>> from jose import jwe
        >>> jwe.encrypt('Hello, World!', 'asecret128bitkey', algorithm='dir', encryption='A128GCM')
        'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..McILMB3dYsNJSuhcDzQshA.OfX9H_mcUpHDeRM4IA.CcnTWqaqxNsjT4eCaUABSg'

When a PBES2 key management algorithm is used, the password is stretched
with PBKDF2. The "p2s" salt and "p2c" iteration count are negotiated
automatically (a fresh 128-bit salt and 8192 iterations by default) and
carried in the protected header:

.. code:: python

        >>> from jose import jwe
        >>> jwe.encrypt('Hello, World!', 'a strong passphrase',
        ...             algorithm='PBES2-HS256+A128KW', encryption='A128GCM')
        b'eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJjIjo4...'


Decrypting Payloads
--------------------------

.. code:: python

        >>> from jose import jwe
        >>> jwe.decrypt('eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..McILMB3dYsNJSuhcDzQshA.OfX9H_mcUpHDeRM4IA.CcnTWqaqxNsjT4eCaUABSg', 'asecret128bitkey')
        'Hello, World!'
