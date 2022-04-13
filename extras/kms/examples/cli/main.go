package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/examples/v2"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
)

const globalScope = "global"

// default to an aead root kms
const rootKmsAeadTemplate = `
kms "aead" {
	purpose = "root"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_root"
}`

// support the --use-transit flag which requires the caller to run:
// "docker-compose up" before executing the example
const rootKmsTransitHcl = `
kms "transit" {
	purpose            = "root"
	address            = "http://localhost:8200"
	token              = "vault-plaintext-root-token"
	disable_renewal    = "false"  
	key_name           = "examplekey"
	mount_path         = "transit/"
	namespace          = "ns1/"
}`

func main() {
	mainCtx := context.Background()

	debug := flag.Bool("debug", false, "enable debug")
	pt := flag.String("plaintext", "default plaintext secret", "plaintext you'd like to use for encrypt/decrypt ops with a wrapper")
	useTransit := flag.Bool("use-transit", false, `use vault transit as the root wrapper source - run "docker-compose up" first`)
	flag.Parse()

	var kmsHcl string
	switch {
	case *useTransit:
		kmsHcl = rootKmsTransitHcl
	default:
		key := examples.GenerateKey()
		kmsHcl = fmt.Sprintf(rootKmsAeadTemplate, key)
	}

	// get the root wrapper from the provided configuration hcl
	rootWrapper, err := examples.RootWrapperFromConfig(mainCtx, kmsHcl, *useTransit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to get root wrapper from config: %s\n\n", err)
		return
	}
	// open the db and run migrations for both for the kms and this cli app.
	// the cli app migration adds a scope table and a fk to the kms_root_key
	// table.
	rw, err := examples.OpenDB(mainCtx, *debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open db: %s\n\n", err)
		return
	}
	// create a kms that supports both the default kms.KeyPurposeRootKey KEK and
	// a "database" DEK
	k, err := kms.New(rw, rw, []kms.KeyPurpose{"database"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init kms: %s\n\n", err)
		return
	}

	// add the external root key wrapper.
	if err := k.AddExternalWrapper(mainCtx, kms.KeyPurposeRootKey, rootWrapper); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add root key: %s\n\n", err)
		return
	}

	// Create the global scope and it's related kms wrappers
	if _, err := rw.DoTx(mainCtx, func(error) bool { return false }, 10, dbw.ExpBackoff{},
		func(r dbw.Reader, w dbw.Writer) error {
			if err := w.Create(mainCtx, &examples.Scope{PrivateId: globalScope}, dbw.WithLookup(true)); err != nil {
				return err
			}
			if err := k.CreateKeys(mainCtx, globalScope, []kms.KeyPurpose{"database"}, kms.WithReaderWriter(r, w)); err != nil {
				return err
			}
			return nil
		}); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create scope and its keys: %s\n\n", err)
		return
	}

	// get the db wrapper (DEK)
	dbWrapper, err := k.GetWrapper(mainCtx, globalScope, "database")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get wrapper for database: %s\n\n", err)
		return
	}

	// get the DEK's key id so we can save it with the oidc row (since it will
	// be used to encrypt/decrypt ciphertext in the row)
	dbWrapperKeyId, err := dbWrapper.KeyId(mainCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get key id: %s\n\n", err)
		return
	}

	oidcId, err := dbw.NewId("oidc")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get oidc id: %s\n\n", err)
		return
	}
	// init a new OIDC record and initialize it's client_secret with our
	// plaintext secret (pt)
	o := &examples.OIDC{
		PrivateId:    oidcId,
		ClientId:     "example-client-id",
		ClientSecret: *pt,
		KeyId:        dbWrapperKeyId,
	}

	fmt.Fprintf(os.Stderr, "using the structwrapping pkg to wrap (encrypt) the new oidc record...\n")
	if err := structwrapping.WrapStruct(mainCtx, dbWrapper, o); err != nil {
		fmt.Fprintf(os.Stderr, "failed to wrap: %s\n\n", err)
		return
	}
	if o.CtClientSecret == nil {
		fmt.Fprintf(os.Stderr, "failed to encrypt the client_secret: %s\n\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "writing the oidc record to the db...\n")
	if _, err := rw.DoTx(mainCtx, func(error) bool { return false }, 10, dbw.ExpBackoff{},
		func(r dbw.Reader, w dbw.Writer) error {
			if err := w.Create(mainCtx, o, dbw.WithLookup(true)); err != nil {
				return err
			}
			return nil
		}); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create oidc resource: %s\n\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "reading the oidc record from the db...\n")
	found := examples.OIDC{
		PrivateId: o.PrivateId,
	}
	if err := rw.LookupBy(mainCtx, &found); err != nil {
		fmt.Fprintf(os.Stderr, "failed to lookup oidc: %s\n\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "using the structwrapping pkg to unwrap (decrypt) the oidc record read from the db...\n")
	if err := structwrapping.UnwrapStruct(mainCtx, dbWrapper, &found); err != nil {
		fmt.Fprintf(os.Stderr, "failed to unwrap: %s\n\n", err)
		return
	}

	if string(found.ClientSecret) != *pt {
		fmt.Fprintf(os.Stderr, "%q doesn't equal %q\n\n", string(found.ClientSecret), *pt)
		return
	}

	fmt.Fprintf(os.Stderr, "successfully encrypted/decrypted %q using the kms\n", *pt)

	fmt.Fprintf(os.Stderr, "attempting to delete scope with its associated DEKs...\n")
	if _, err := rw.DoTx(mainCtx, func(error) bool { return false }, 10, dbw.ExpBackoff{},
		func(r dbw.Reader, w dbw.Writer) error {
			rowsDeleted, err := w.Delete(mainCtx, &examples.Scope{PrivateId: globalScope})
			if err != nil {
				return err
			}
			if rowsDeleted != 1 {
				return fmt.Errorf("%q rows delete and only wanted 1", rowsDeleted)
			}
			return nil
		}); err == nil {
		fmt.Fprintf(os.Stderr, "whoa... we should have failed to delete scope and its keys, since there's a FK to the oidc record\n\n")
		return
	}

	fmt.Fprintf(os.Stderr, "attempting to first delete the oidc record, then delete scope with its associated DEKs...\n")
	if _, err := rw.DoTx(mainCtx, func(error) bool { return false }, 10, dbw.ExpBackoff{},
		func(r dbw.Reader, w dbw.Writer) error {
			_, err := w.Delete(mainCtx, &found)
			if err != nil {
				return err
			}

			_, err = w.Delete(mainCtx, &examples.Scope{PrivateId: globalScope})
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
		fmt.Fprintf(os.Stderr, "failed to delete scope and its keys: %s\n\n", err)
		return
	}

	// TODO (jimlambrt 4/2022) we need to provide some method to clear the cache
	// when the caller knows it's out of sync with the db (source of truth).
	// Once that's implemented, we can uncomment this code, nerf the cache and
	// make sure the database key is no longer in the cache.
	// // get the db wrapper and do some crypto operations with it.
	// dbWrapper, err = k.GetWrapper(mainCtx, globalScope, "database")
	// if err != kms.ErrKeyNotFound {
	// 	fmt.Fprintf(os.Stderr, "failed to delete keys for scope\n\n")
	// 	return
	// }

	// re-init the kms (see TODO above)
	k, err = kms.New(rw, rw, []kms.KeyPurpose{"database"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init kms: %s\n\n", err)
		return
	}

	// re-add the external root key wrapper.
	if err := k.AddExternalWrapper(mainCtx, kms.KeyPurposeRootKey, rootWrapper); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add root key: %s\n\n", err)
		return
	}
	dbWrapper, err = k.GetWrapper(mainCtx, globalScope, "database")
	if err != nil && !errors.Is(err, kms.ErrKeyNotFound) {
		fmt.Fprintf(os.Stderr, "failed to delete keys for scope: %s\n\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "deleted the global scope and its related key wrappers\n")
	fmt.Fprintf(os.Stderr, "done!\n")

}
