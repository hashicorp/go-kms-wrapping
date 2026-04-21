// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package examples

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2"
	"github.com/hashicorp/go-secure-stdlib/configutil/v2"
)

// RootWrapperFromConfig returns the root wrapper from the provided kms hcl
func RootWrapperFromConfig(ctx context.Context, kmsHcl string, useTransit bool) (wrapping.Wrapper, error) {
	parsedKmsConfig, err := parseConfig(kmsHcl)
	if err != nil {
		return nil, err
	}
	var rootWrapper wrapping.Wrapper
	switch {
	case useTransit:
		fmt.Fprintf(os.Stderr, "using a vault transit root wrapper from: %s\n", parsedKmsConfig.Config["address"])
		w := transit.NewWrapper()
		_, err := w.SetConfig(ctx,
			transit.WithAddress(parsedKmsConfig.Config["address"]),
			transit.WithToken(parsedKmsConfig.Config["token"]),
			transit.WithKeyName(parsedKmsConfig.Config["key_name"]),
			transit.WithMountPath(parsedKmsConfig.Config["mount_path"]),
			transit.WithNamespace(parsedKmsConfig.Config["namespace"]),
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error configuring the vault transit root wrapper.\n")
			fmt.Fprintf(os.Stderr, "did you start vault via with docker-compose in the parent directory?\n")
			return nil, err
		}
		rootWrapper = w
	default:
		fmt.Fprintf(os.Stderr, "using a generated aead key root wrapper...\n")
		w := aead.NewWrapper()
		if _, err := w.SetConfig(ctx, wrapping.WithKeyId(parsedKmsConfig.Config["key_id"])); err != nil {
			return nil, err
		}
		decodedKey, err := base64.StdEncoding.DecodeString(parsedKmsConfig.Config["key"])
		if err != nil {
			return nil, err
		}
		if err := w.SetAesGcmKeyBytes([]byte(decodedKey)); err != nil {
			return nil, err
		}
		rootWrapper = w
	}

	return rootWrapper, nil
}

// GenerateKey will generate an example key
func GenerateKey() string {
	var numBytes int64 = 32
	randBuf := new(bytes.Buffer)
	n, err := randBuf.ReadFrom(&io.LimitedReader{
		R: rand.Reader,
		N: numBytes,
	})
	if err != nil {
		panic(err)
	}
	if n != numBytes {
		panic(fmt.Errorf("expected to read 64 bytes, read %d", n))
	}
	return base64.StdEncoding.EncodeToString(randBuf.Bytes()[0:32])
}

func parseConfig(d string) (*configutil.KMS, error) {
	sharedConfig, err := configutil.ParseConfig(d)
	if err != nil {
		return nil, err
	}
	if len(sharedConfig.Seals) != 1 {
		return nil, fmt.Errorf("expected 1 seal and got %d", len(sharedConfig.Seals))
	}
	return sharedConfig.Seals[0], nil
}
