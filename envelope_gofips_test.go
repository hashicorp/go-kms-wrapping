// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build gofips

package wrapping

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	legacyAEAD, err := cipher.NewGCM(block)
	require.NoError(t, err)
	plaintext := []byte("legacy envelope")
	envelope := &EnvelopeInfo{
		Ciphertext: legacyAEAD.Seal(nil, nonce, plaintext, nil),
		Key:        key,
		Iv:         nonce,
	}

	decrypted, err := EnvelopeDecrypt(envelope)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}
