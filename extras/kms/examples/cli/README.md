# cli
An example go-kms-wrapping extras/kms CLI that demonstrates how to incorporate a
Kms into an application.   

The application defines a `scope` table and the migrations for the CLI define a
FK between the `kms_root_key` and the `scope` table.   

Just a reminder, that a `scope` defines ownership for a set of kms DEKs (data
encryption keys).  For example an application could choose to only have a global
scope or perhaps it could decide to have scopes for each organization and
project represented in application.  It's completely up to the app to decide
what sort of model it wants to use for scopes, but the kms requires an app to
define at least one scope.

Running the cli will:
- Initialize a root wrapper using either a vault transit wrapper or a
  self-generated key wrapper
- Create a global scope with a database DEK
- Encrypt a plaintext secret using the global scope database DEK and store
  that secret in an oidc entry in the database.
- Retrieve the oidc entry and decrypt the cipher text secret using the global scope database DEK.
- Validate that the decrypted secret matches the original secret.
- Delete the oidc entry. 
- Before exiting, it will delete the global scope and all the DEKs associated
  with it.  NOTE: typically you won't do this delete, but it's included in the
  example to demonstrate why it's important to declare a FK between your scope
  table and the kms_root_key table in order to prevent orphan wrappers when your
  app deletes an unneeded scope.   

Expected output from a successful execution:
```
❯ ./cli --use-transit --plaintext "test secret"
using a vault transit root wrapper from: http://localhost:8200
using the structwrapping pkg to wrap (encrypt) the new oidc record...
writing the oidc record to the db...
reading the oidc record from the db...
using the structwrapping pkg to unwrap (decrypt) the oidc record read from the db...
successfully encrypted/decrypted "test secret" using the kms
attempting to delete scope with its associated DEKs...
attempting to first delete the oidc record, then delete scope with its associated DEKs...
deleted the global scope and its related key wrappers
done!
```

<hr>

Build the example:
```
go build
```
Usage:
```
./cli -h
Usage of ./cli:
  -debug
        enable debug
  -plaintext string
        plaintext you'd like to use for encrypt/decrypt ops with a wrapper (default "default plaintext secret")
  -use-transit
        use vault transit as the root wrapper source - run "docker-compose up" first
```
To Use [Vault's Transit Secrets
Engine](https://www.vaultproject.io/docs/secrets/transit) as your root wrapper
you must first start vault with docker-compose which is located in the parent
directory. 
```
cd ..
docker-compose up
```
Then in a separate terminal, run the cli passing the  `use-transit` flag:
```
./cli --use-transit
```

<hr>                                                           

### High-level ERD     
The example CLI extends the existing kms schema by adding a `scope` table and
declares a cascading FK between scopes and kms_root_keys.  If a `scope` is
deleted, then all of its associated wrappers will be deleted.  With that said,
the schema also includes an `oidc` entity and declares a restricted FK between
`kms_data_key_version` and `oidc`.  Given this restricted FK, you can't deleted
a `kms_data_key_version` if there's an existing `oidc` entry that uses it. 

This schema with its FKs ensures that a wrapper can't be deleted if it's
currently in use.  As a result, you'll always be able to decrypt an `oidc` entry
that's stored in the database.

```                                                     
    ┌────────────────────────┐                                   
    │         scope          │                                   
    ├────────────────────────┤                                   
 ┌─┼│private_id              │                                   
 │  │                        │                                   
 │  │                        │                                   
 │  └────────────────────────┘                                   
 │                                                               
 │                                                               
 │               ┌───────────────────────────────┐               
 │               │                               ○               
 │               ┼                               ┼               
 │  ┌────────────────────────┐      ┌────────────────────────┐   
 │  │      kms_root_key      │      │      kms_data_key      │   
 │  ├────────────────────────┤      ├────────────────────────┤   
 └○┼│private_id              │      │private_id              │   
    │scope_id                │      │root_key_id             │   
    │                        │      │purpose                 │   
    └────────────────────────┘      │                        │   
                 ┼                  └────────────────────────┘   
                 │                               ┼               
                 │                               │               
                 │                               │               
                 │                               │               
                 ┼                               ┼               
                ╱│╲                             ╱│╲              
    ┌────────────────────────┐      ┌────────────────────────┐   
    │  kms_root_key_version  │      │  kms_data_key_version  │   
    ├────────────────────────┤      ├────────────────────────┤   
    │private_id              │      │private_id              │   
    │root_key_id             │      │data_key_id             │┼─┐
    │key                     │      │root_key_id             │  │
    │version                 │      │key                     │  │
    │                        │      │version                 │  │
    └────────────────────────┘      └────────────────────────┘  │
                 ┼                               ┼              │
                 │                               ○              │
                 └───────────────────────────────┘              │
                                                                │
                                                                │
                                    ┌────────────────────────┐  │
                                    │          oidc          │  │
                                    ├────────────────────────┤  │
                                    │private_id              │╲ │
                                    │client_id               │─○┘
                                    │client_secret           │╱  
                                    │key_id                  │   
                                    │                        │   
                                    └────────────────────────┘   
```