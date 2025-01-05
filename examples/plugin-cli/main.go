// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"os"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead" // a built-in go-kms-wrapping wrapper (no additional dependencies)
	configutil "github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
)

// support the --use-transit flag which requires the caller to run:
// "docker-compose up" before executing the example
const rootKmsTransitHcl = `
kms "azurekeyvault" {
  purpose        = "recovery"
  vault_name     = "boundary-97at"
  key_name       = "recovery"
}`

func main() {
	mainCtx := context.Background()

	pt := flag.String("plaintext", "default plaintext secret", "plaintext you'd like to use for encrypt/decrypt ops with a wrapper")
	flag.Parse()

	fmt.Fprintf(os.Stderr, "initializing the vault transit plugin wrapper\n")
	wrapper, cleanupFn, err := newVaultTransitPluginWrapper(mainCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to initialize vault transit plugin wrapper: %s\n\n", err)
		fmt.Fprintf(os.Stderr, `did you run "docker-compose up" first`)
		return
	}
	if cleanupFn != nil {
		defer cleanupFn()
	}

	fmt.Fprintf(os.Stderr, "encrypting the plaintext: %q\n", *pt)
	cipherText, err := wrapper.Encrypt(mainCtx, []byte(*pt))
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to encrypt plaintext: %s\n\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "decrypting the ciphertext\n")
	decryptedPlaintext, err := wrapper.Decrypt(mainCtx, cipherText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to decrypt ciphertext: %s\n\n", err)
		return
	}
	if string(decryptedPlaintext) != *pt {
		fmt.Fprintf(os.Stderr, "%q doesn't equal %q\n\n", string(decryptedPlaintext), *pt)
		return
	}

	fmt.Fprintf(os.Stderr, "successfully encrypted/decrypted %q using the plugin\n", *pt)
	fmt.Fprintf(os.Stderr, "done!\n")
}

// newVaultTransitPluginWrapper will initialize a vault transit wrapper
func newVaultTransitPluginWrapper(ctx context.Context) (wrapping.Wrapper, func() error, error) {
	const (
		op = "kms.NewVaultTransitRootWrapper"

		kmsPluginPrefix = "plugin-"
	)
	wrapperCfg, err := configutil.ParseConfig(rootKmsTransitHcl)
	if err != nil {
		return nil, nil, err
	}
	if len(wrapperCfg.Seals) != 1 {
		return nil, nil, fmt.Errorf("expected 1 seal and got %d", len(wrapperCfg.Seals))
	}
	fmt.Fprintf(
		os.Stderr,
		"configuring/initializing %s plugin for address: %s\n",
		wrapperCfg.Seals[0].Type,
		wrapperCfg.Seals[0].Config["address"],
	)
	wrapper, cleanup, err := configutil.ConfigureWrapper(
		ctx,
		wrapperCfg.Seals[0],
		nil,
		nil,
		configutil.WithPluginOptions(
			pluginutil.WithPluginsMap(builtinKmsPlugins()),
			pluginutil.WithPluginsFilesystem(kmsPluginPrefix, assetsFileSystem()),
		),
		configutil.WithLogger(hclog.NewNullLogger()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("Error configuring kms: %w", err)
	}

	return wrapper, cleanup, nil
}

func builtinKmsPlugins() map[string]pluginutil.InmemCreationFunc {
	return map[string]pluginutil.InmemCreationFunc{
		"aead": func() (interface{}, error) {
			return aead.NewWrapper(), nil
		},
	}
}

// content is our static web server content.
//
//go:embed plugins/ass
//go:embed plugins/assets
var content embed.FS

func assetsFileSystem() fs.FS {
	const contentDir = "plugins/assets"

	// Remove the root
	f, err := fs.Sub(content, contentDir)
	if err != nil {
		panic(err)
	}
	return f
}
