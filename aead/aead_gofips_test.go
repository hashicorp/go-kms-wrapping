// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build gofips

package aead

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

type nonComparableReader []byte

func (reader nonComparableReader) Read(destination []byte) (int, error) {
	return copy(destination, reader), nil
}

func TestWrapperGoFipsRandomNonceFormat(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte("hello")
	wrapper := newTestWrapper(t)

	blob, err := wrapper.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	require.Len(t, blob.Ciphertext, len(plaintext)+12+16)

	secondBlob, err := wrapper.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	require.NotEqual(t, blob.Ciphertext[:12], secondBlob.Ciphertext[:12])

	decrypted, err := wrapper.Decrypt(ctx, blob)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestWrapperRandomNonceRejectsCallerNonceSources(t *testing.T) {
	wrapper := newTestWrapper(t)
	ctx := context.Background()

	_, err := wrapper.Encrypt(ctx, []byte("hello"), wrapping.WithIV(make([]byte, 12)))
	require.ErrorContains(t, err, "explicit IV is not supported")

	_, err = wrapper.Encrypt(ctx, []byte("hello"), WithRandomReader(nonComparableReader("random")))
	require.ErrorContains(t, err, "random reader option is not supported")

	_, err = wrapper.Encrypt(ctx, []byte("hello"), WithRandomReader(rand.Reader))
	require.ErrorContains(t, err, "random reader option is not supported")

	_, err = wrapper.Encrypt(ctx, []byte("hello"), WithRandomReader(nil))
	require.NoError(t, err)
}

func TestWrapperDecryptsLegacyCiphertext(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	plaintext := []byte("legacy ciphertext")
	nonce, err := hex.DecodeString("000102030405060708090a0b")
	require.NoError(t, err)
	legacyCiphertext, err := hex.DecodeString("e4ae54336384af9aab083a808f77bb7420b9ad39b531869264e4b86cfb3c707731")
	require.NoError(t, err)
	blob := &wrapping.BlobInfo{
		Ciphertext: append(nonce, legacyCiphertext...),
	}

	wrapper := NewWrapper()
	require.NoError(t, wrapper.SetAesGcmKeyBytes(key))
	decrypted, err := wrapper.Decrypt(ctx, blob)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}
