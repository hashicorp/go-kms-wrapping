// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build !gofips

package wrapping

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnvelopeEncryptUsesExplicitIV(t *testing.T) {
	plaintext := []byte("test")
	iv := []byte("test-with-iv")
	aad := []byte("test aad")

	envelope, err := EnvelopeEncrypt(plaintext, WithIV(iv), WithAad(aad))
	require.NoError(t, err)
	require.Equal(t, iv, envelope.Iv)

	decrypted, err := EnvelopeDecrypt(envelope, WithAad(aad))
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}