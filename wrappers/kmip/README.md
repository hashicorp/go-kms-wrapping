# KMIP wrapper

Provides integration with KMIP v1.2 up to v1.4 compatible servers.

## Settings
| Environment variable       | Required | Default          | Description                                              |
| -------------------------- | -------- | ---------------- | -------------------------------------------------------- |
| BAO_KMIP_WRAPPER_KEY_ID    | yes      |                  | Wrapping key ID (Symmetric Key or Private Key)           |
| BAO_KMIP_ENDPOINT          | yes      |                  | KMIP endpoint address and port                           |
| BAO_KMIP_CA_CERT           | no       |                  | Server CA certificate                                    |
| BAO_KMIP_CLIENT_CERT       | yes      |                  | Client authentication TLS certificate                    |
| BAO_KMIP_CLIENT_KEY        | yes      |                  | Client TLS private key                                   |
| BAO_KMIP_SERVER_NAME       | no       |                  | Used to verify the hostname on the returned certificates |
| BAO_KMIP_TIMEOUT           | no       | 10               | KMIP operation timeout in seconds                        |
| BAO_KMIP_ENCRYPT_ALG       | no       | AES_GCM          | Encryption algorithm to use                              |
| BAO_KMIP_TLS12_CIPHERS     | no       | Golang's default | Comma separated list of TLS 1.2 ciphers to allow         |

## KMIP server requirements
- Must support one of the following KMIP protocol version: v1.2, v1.3 or v1.4.
- Must support Encrypt & Decrypt operations
- Must support AES symmetric keys or RSA key pairs
- Must support one of the following cryptographic parameters combination

## Supported KMIP Encryption Algorithms

### AES_GCM (recommended)
Should be supported on most KMIP 1.4 compatible servers.
Support on KMIP 1.2 and 1.3 vary depending on vendors.

`KMIP_WRAPPER_KEY_ID` must be the Symmetric Key ID.

#### KMIP Cryptographic Parameters
| Parameter               | Value    |
| ----------------------- | -------- |
| Cryptographic Algorithm | AES      |
| Block Cipher Mode       | GCM      |
| Tag length              | 16 bytes |
| Nonce length            | 12 bytes |

### RSA_OAEP_SHA256
`KMIP_WRAPPER_KEY_ID` must be the Private Key ID.

#### KMIP Cryptographic Parameters
| Parameter               | Value    |
| ----------------------- | -------- |
| Cryptographic Algorithm | RSA      |
| Padding Method          | OAEP     |
| Hashing Algorithm       | SHA-256  |
| Mask Generator Function | MGF-1    |
| Mask Generator Hash     | SHA-256  |

### RSA_OAEP_SHA384
`KMIP_WRAPPER_KEY_ID` must be the Private Key ID.

#### KMIP Cryptographic Parameters
| Parameter               | Value    |
| ----------------------- | -------- |
| Cryptographic Algorithm | RSA      |
| Padding Method          | OAEP     |
| Hashing Algorithm       | SHA-384  |
| Mask Generator Function | MGF-1    |
| Mask Generator Hash     | SHA-384  |

### RSA_OAEP_SHA512
`KMIP_WRAPPER_KEY_ID` must be the Private Key ID.

#### KMIP Cryptographic Parameters
| Parameter               | Value    |
| ----------------------- | -------- |
| Cryptographic Algorithm | RSA      |
| Padding Method          | OAEP     |
| Hashing Algorithm       | SHA-512  |
| Mask Generator Function | MGF-1    |
| Mask Generator Hash     | SHA-512  |

## Compatibility
KMIP wrapping has been tested and validated against following implementations
- [PyKMIP](https://github.com/OpenKMIP/PyKMIP)
    - Only `AES_GCM` is supported as PyKMIP does not implement asymmetric encryption.
    - TLS 1.2 cipher `TLS_RSA_WITH_AES_128_CBC_SHA256` had to be allowed in wrapper config.
- [OVHcloud's KMS](https://www.ovhcloud.com/en-ie/identity-security-operations/key-management-service/)