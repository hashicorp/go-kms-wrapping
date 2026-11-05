// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build gofips

package wrapping

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnvelopeRandomNonceFormat(t *testing.T) {
	plaintext := []byte("test")
	envelope, err := EnvelopeEncrypt(plaintext)
	require.NoError(t, err)
	require.Len(t, envelope.Iv, 12)
	require.Len(t, envelope.Ciphertext, len(plaintext)+16)

	secondEnvelope, err := EnvelopeEncrypt(plaintext)
	require.NoError(t, err)
	require.NotEqual(t, envelope.Iv, secondEnvelope.Iv)

	decrypted, err := EnvelopeDecrypt(envelope)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestEnvelopeEncryptRejectsExplicitIV(t *testing.T) {
	_, err := EnvelopeEncrypt([]byte("test"), WithIV(make([]byte, 12)))
	require.ErrorContains(t, err, "explicit IV is not supported")
}

func TestEnvelopeDecryptsLegacyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	nonce, err := hex.DecodeString("000102030405060708090a0b")
	require.NoError(t, err)
	plaintext := []byte("legacy ciphertext")
	ciphertext, err := hex.DecodeString("e4ae54336384af9aab083a808f77bb7420b9ad39b531869264e4b86cfb3c707731")
	require.NoError(t, err)
	envelope := &EnvelopeInfo{
		Ciphertext: ciphertext,
		Key:        key,
		Iv:         nonce,
	}

	decrypted, err := EnvelopeDecrypt(envelope)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}
