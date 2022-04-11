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
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

const globalScope = "global"

// default to an aead root kms
const rootKmsAead = `
kms "aead" {
	purpose = "root"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_root"
}`

// support the --use-transit flag which requires the caller to run:
// "docker-compose up" before executing the example
const rootKmsTransit = `
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
		kmsHcl = rootKmsTransit
	default:
		key := examples.GenerateKey()
		kmsHcl = fmt.Sprintf(rootKmsAead, key)
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
	rw, err := examples.OpenDB(mainCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open db: %s\n\n", err)
		return
	}
	if *debug {
		rw.DB().Debug(true)
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
			if err := w.Create(mainCtx, &examples.Scope{PrivateId: globalScope}); err != nil {
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

	// get the db wrapper and do some crypto operations with it.
	dbWrapper, err := k.GetWrapper(mainCtx, globalScope, "database")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get wrapper for database: %s\n\n", err)
		return
	}
	ct, err := dbWrapper.Encrypt(mainCtx, []byte(*pt))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encrypt plaintext: %s\n\n", err)
		return
	}
	keyId, err := dbWrapper.KeyId(mainCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get key id: %s\n\n", err)
		return
	}
	got, err := dbWrapper.Decrypt(mainCtx, ct, wrapping.WithKeyId(keyId))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to decrypt ciphertext: %s\n\n", err)
		return
	}

	if string(got) != *pt {
		fmt.Fprintf(os.Stderr, "%q doesn't equal %q\n\n", string(got), *pt)
		return
	}

	fmt.Fprintf(os.Stderr, "encrypted/decrypted %q using the kms\n", *pt)

	// Delete the global scope and it's related kms wrappers. NOTE: this is why it's
	// important to define FK, so there are no orphan wrappers when a scope is deleted.
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
