# Go-KMS-Wrapping
----

NOTE: Currently no compatibility guarantees are provided for this library; we expect tags to remain in the `0.x.y` range.

Go-KMS-Wrapping is a library that can be used to encrypt things through various KMS providers -- public clouds, Vault's Transit plugin, etc. It is similar in concept to various other cryptosystems but focuses on using third party KMSes. This library is the underpinning of Vault's auto-unseal functionality. Currently this library serves the needs of Vault, but is relatively simply and should be ready to use for many other applications.

For KMS providers that do not support encrypting arbitrarily large values, the library will generate an encryption key, encrypt the value with it, and use the KMS to encrypt this DEK.

The key being used by a given implementation can change; the library stores key information actually used to encrypt a given value as part of the returned data, and this key will be used for decryption. By extension, this means that users should be careful not to delete keys simply because they're not configured to be used by this library, as they may have been used for past encryption operations.