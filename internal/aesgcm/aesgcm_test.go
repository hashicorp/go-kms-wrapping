// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build !gofips

package aesgcm

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewStandard(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 32))
	require.NoError(t, err)

	standard, err := New(block)
	require.NoError(t, err)
	require.Equal(t, 12, standard.NonceSize())
}
