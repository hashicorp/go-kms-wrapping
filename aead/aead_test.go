// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package aead

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

func TestShamirVsAEAD(t *testing.T) {
	ctx := context.Background()
	a := NewWrapper()
	typ, err := a.Type(ctx)
	require.NoError(t, err)
	require.Equal(t, typ, wrapping.WrapperTypeAead)

	s := NewShamirWrapper()
	typ, err = s.Type(ctx)
	require.NoError(t, err)
	require.Equal(t, typ, wrapping.WrapperTypeShamir)
}

func Test_Wrapper(t *testing.T) {
	root := NewWrapper()
	encBlob := testWrapperBasic(t, root)
	testDerivation(t, root, encBlob)
}

func testWrapperBasic(t *testing.T, root wrapping.Wrapper) *wrapping.BlobInfo {
	require := require.New(t)
	ctx := context.Background()

	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}

	_, err = root.SetConfig(
		context.Background(),
		wrapping.WithKeyId("root"),
		wrapping.WithConfigMap(map[string]string{
			"key": base64.StdEncoding.EncodeToString(rootKey),
		}),
	)
	require.NoError(err)

	keyId, err := root.KeyId(ctx)
	require.NoError(err)
	require.Equal(keyId, "root")

	encBlob, err := root.Encrypt(context.Background(), []byte("foobar"))
	require.NoError(err)

	// Sanity check
	decVal, err := root.Decrypt(context.Background(), encBlob)
	require.NoError(err)
	require.Equal("foobar", string(decVal))

	return encBlob
}

func testDerivation(t *testing.T, root *Wrapper, encBlob *wrapping.BlobInfo) {
	ctx := context.Background()
	require := require.New(t)

	sub, err := root.NewDerivedWrapper(
		wrapping.WithKeyId("sub"),
		wrapping.WithConfigMap(map[string]string{
			"salt": base64.StdEncoding.EncodeToString([]byte("zip")),
			"info": base64.StdEncoding.EncodeToString([]byte("zap")),
		}),
	)
	require.NoError(err)
	keyId, err := sub.KeyId(ctx)
	require.NoError(err)
	require.Equal("sub", keyId)

	// This should fail as it should be a different key
	decVal, err := sub.Decrypt(context.Background(), encBlob)
	require.Error(err)
	require.Nil(decVal)

	subEncBlob, err := sub.Encrypt(context.Background(), []byte("foobar"))
	require.NoError(err)
	require.NotNil(subEncBlob)

	// Sanity check
	subDecVal, err := sub.Decrypt(context.Background(), subEncBlob)
	require.NoError(err)
	require.Equal("foobar", string(subDecVal))
	require.NotNil(subDecVal)

	// This should fail too
	decVal, err = root.Decrypt(context.Background(), subEncBlob)
	require.Error(err)
	require.Nil(decVal)

	// Ensure that deriving a second subkey with the same params works. Use
	// direct options values this time.
	sub2, err := root.NewDerivedWrapper(
		wrapping.WithKeyId("sub2"),
		WithSalt([]byte("zip")),
		WithInfo([]byte("zap")),
	)
	require.NoError(err)
	keyId, err = sub2.KeyId(ctx)
	require.NoError(err)
	require.Equal("sub2", keyId)

	subDecVal, err = sub2.Decrypt(context.Background(), subEncBlob)
	require.NoError(err)
	require.Equal("foobar", string(subDecVal))
	require.NotNil(subDecVal)

	// Ensure that a subkey with different params doesn't work
	subBad, err := root.NewDerivedWrapper(
		wrapping.WithKeyId("sub2"),
		wrapping.WithConfigMap(map[string]string{
			"salt": base64.StdEncoding.EncodeToString([]byte("zap")),
			"info": base64.StdEncoding.EncodeToString([]byte("zip")),
		}),
	)
	require.NoError(err)
	subDecVal, err = subBad.Decrypt(context.Background(), subEncBlob)
	require.Error(err)
	require.Nil(subDecVal)
}

// newTestKey generates a random 32-byte AES key for use in tests.
func newTestKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

// newTestWrapper returns a Wrapper configured with a fresh random key.
func newTestWrapper(t *testing.T) *Wrapper {
	t.Helper()
	w := NewWrapper()
	require.NoError(t, w.SetAesGcmKeyBytes(newTestKey(t)))
	return w
}

// Test_Encrypt_WithIV covers all four nonce-handling cases in Encrypt.
func Test_Encrypt_WithIV(t *testing.T) {
	ctx := context.Background()

	t.Run("explicit nonce via WithIV", func(t *testing.T) {
		w := newTestWrapper(t)
		iv := make([]byte, 12)
		_, err := rand.Read(iv)
		require.NoError(t, err)

		blob, err := w.Encrypt(ctx, []byte("hello"), wrapping.WithIV(iv))
		require.NoError(t, err)
		// The prepended nonce in the blob should match what we supplied.
		require.Equal(t, iv, blob.Ciphertext[:12])

		plain, err := w.Decrypt(ctx, blob)
		require.NoError(t, err)
		require.Equal(t, "hello", string(plain))
	})

	t.Run("WithIV wrong length returns error", func(t *testing.T) {
		w := newTestWrapper(t)
		_, err := w.Encrypt(ctx, []byte("hello"), wrapping.WithIV([]byte("short")))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid IV length")
	})

	t.Run("random nonce generated when WithIV not set", func(t *testing.T) {
		w := newTestWrapper(t)
		blob, err := w.Encrypt(ctx, []byte("hello"))
		require.NoError(t, err)
		// Ciphertext must be longer than the 12-byte nonce prefix.
		require.Greater(t, len(blob.Ciphertext), 12)

		plain, err := w.Decrypt(ctx, blob)
		require.NoError(t, err)
		require.Equal(t, "hello", string(plain))
	})
}

// Test_SetAead_RandomNonce covers the NonceSize()==0 path (cipher.NewGCMWithRandomNonce).
func Test_SetAead_RandomNonce(t *testing.T) {
	ctx := context.Background()

	newRandomNonceAead := func(t *testing.T) cipher.AEAD {
		t.Helper()
		block, err := aes.NewCipher(newTestKey(t))
		require.NoError(t, err)
		aead, err := cipher.NewGCMWithRandomNonce(block)
		require.NoError(t, err)
		return aead
	}

	t.Run("encrypt and decrypt round-trip", func(t *testing.T) {
		w := NewWrapper()
		w.SetAead(newRandomNonceAead(t))

		blob, err := w.Encrypt(ctx, []byte("hello"))
		require.NoError(t, err)

		plain, err := w.Decrypt(ctx, blob)
		require.NoError(t, err)
		require.Equal(t, "hello", string(plain))
	})

	t.Run("WithIV rejected when NonceSize is 0", func(t *testing.T) {
		w := NewWrapper()
		w.SetAead(newRandomNonceAead(t))

		_, err := w.Encrypt(ctx, []byte("hello"), wrapping.WithIV(make([]byte, 12)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "WithIV must not be set")
	})

	t.Run("decrypt with mismatched AEAD nonce size fails", func(t *testing.T) {
		// Use the same key for both wrappers; the only difference is the nonce
		// size used by each AEAD.
		key := newTestKey(t)

		// Encrypt with a 24-byte-nonce GCM variant. The wrapper prepends the
		// 24-byte nonce to the ciphertext in BlobInfo.Ciphertext.
		wEnc := NewWrapper()
		block, err := aes.NewCipher(key)
		require.NoError(t, err)
		largeNonceAead, err := cipher.NewGCMWithNonceSize(block, 24)
		require.NoError(t, err)
		wEnc.SetAead(largeNonceAead)

		blob, err := wEnc.Encrypt(ctx, []byte("hello"))
		require.NoError(t, err)

		// Attempt to decrypt with standard cipher.NewGCM (NonceSize == 12).
		// It slices only 12 bytes as the nonce, leaving the remaining 12 bytes
		// of the actual nonce inside the "ciphertext" and decrypt fails.
		wDec := NewWrapper()
		require.NoError(t, wDec.SetAesGcmKeyBytes(key))

		_, err = wDec.Decrypt(ctx, blob)
		require.Error(t, err)
	})
}
