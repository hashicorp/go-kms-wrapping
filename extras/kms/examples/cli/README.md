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

<hr>

### Running the CLI
Build the example:
```
go build
```
Runing the cli will:
- Initialize a root wrapper
- Create a global scope with a database DEK
- Encrypt/decrypt a default string using the database DEK.  
- Before exiting, it will delete the global scope and all the DEKs associated
  with it.  

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

