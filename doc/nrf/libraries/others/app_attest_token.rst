.. _lib_app_attest_token:

Application attestation token
#############################

.. contents::
   :local:
   :depth: 2

The Application attestation token library generates a device attestation token on the nRF92 Series application core.

Attestation tokens are used to verify the authenticity of the device.
An attestation token includes the device's internal UUID.
An attestation token consists of two base64url strings separated by a dot (``.``).
The format is ``base64url1.base64url2``.
The first base64url string (``base64url1``) is the Device Identity Attestation message, which is a CBOR encoded payload containing the device UUID, device type, and a nonce.
The second base64url string (``base64url2``) is the `CBOR Object Signing and Encryption (COSE)`_ authentication metadata.

To use the library to obtain an attestation token, complete the following steps:

1. Enable the Application attestation token library (:kconfig:option:`CONFIG_APP_ATTEST_TOKEN`).
#. Allocate a buffer of at least :c:macro:`APP_ATTEST_TOKEN_BUF_SZ` bytes.
#. Call the :c:func:`app_attest_token_get` function to obtain the token string.

Optionally, pass a 16-byte challenge to :c:func:`app_attest_token_get` to embed it as the token nonce.
If the challenge pointer is NULL, the library generates a random nonce.

Configuration
*************

Configure the following options when using this library:

* :kconfig:option:`CONFIG_APP_ATTEST_TOKEN`

API documentation
*****************

| Header file: :file:`include/app_attest_token.h`
| Source file: :file:`lib/app_attest_token/app_attest_token.c`

.. doxygengroup:: app_attest_token
