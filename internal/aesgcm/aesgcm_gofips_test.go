// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build gofips

package aesgcm

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewGoFips(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 32))
	require.NoError(t, err)

	managed, err := New(block)
	require.NoError(t, err)
	require.Zero(t, managed.NonceSize())
}
