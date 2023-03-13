// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// Sha256Sum computes SHA256 message digest (compatible/comparable with GNU
// sha256sum)
func Sha256Sum(ctx context.Context, r io.Reader) (string, error) {
	const op = "crypto.Sha256Sum"
	switch {
	case isNil(r):
		return "", fmt.Errorf("%s: missing reader: %w", op, wrapping.ErrInvalidParameter)
	}

	hasher := sha256.New()

	if _, err := io.Copy(hasher, r); err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	hash := hasher.Sum(nil)
	encodedHex := hex.EncodeToString(hash[:])
	return encodedHex, nil
}
