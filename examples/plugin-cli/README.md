# plugin-cli
An example CLI that demonstrates how to incorporate a
[go-plugin](https://github.com/hashicorp/go-plugin) wrapper into an application.
In this example, we'll use a Vault `transit` go-plugin.

Why would you want to use a Vault `transit` via a
[go-plugin](https://github.com/hashicorp/go-plugin) vs. just including the
wrapper dependency directly into your application?  Well, let's say you wanted
to allow users to chose from a variety of KMS wrappers within your application,
via configuration but you didn't want to include every possible KMS wrapper
dependency into your application.  Using go-plugin wrappers allows you to build
a set of kms wrappers as plugins and perhaps embed the plugin binaries into your
app (like we do in this example).  Then your app has no direct dependencies on
the KMS's you wish to support.


Running the cli will:
- Initialize a Vault `transit` plugin.
- Encrypt a plaintext secret using the plugin Vault `transit` wrapper.
- Decrypt the cipher text secret using the plugin Vault `transit` wrapper.
- Validate that the decrypted plaintext matches the original plaintext.

Expected output from a successful execution:
```
❯ ./plugin-cli --plaintext "test secret"
initializing the vault transit plugin wrapper
configuring/initializing transit plugin for address: http://localhost:8200
encrypting the plaintext: "test secret"
decrypting the ciphertext
successfully encrypted/decrypted "test secret" using the plugin
done!d the global scope and its related key wrappers
done!
```

<hr>

Build the example:
```
make 
```
Before running the example, you must first start Vault with docker-compose. 
```
cd ..
docker-compose up
```
Usage:
```
❯ ./plugin-cli -h
Usage of ./plugin-cli:
  -plaintext string
        plaintext you'd like to use for encrypt/decrypt ops with a wrapper (default "default plaintext secret")
```

