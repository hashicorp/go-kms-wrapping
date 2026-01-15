// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package multi_test

import (
	"context"
	"crypto/rand"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/multi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPooledWrapper(t *testing.T) {
	ctx := context.Background()

	w1Key := make([]byte, 32)
	n, err := rand.Read(w1Key)
	require.NoError(t, err)
	require.Equal(t, n, 32)

	w1 := aead.NewWrapper()
	_, err = w1.SetConfig(ctx, wrapping.WithKeyId("w1"))
	require.NoError(t, err)
	require.NoError(t, w1.SetAesGcmKeyBytes(w1Key))

	w2Key := make([]byte, 32)
	n, err = rand.Read(w2Key)
	require.NoError(t, err)
	require.Equal(t, n, 32)

	w2 := aead.NewWrapper()
	_, err = w2.SetConfig(ctx, wrapping.WithKeyId("w2"))
	require.NoError(t, err)
	require.NoError(t, w2.SetAesGcmKeyBytes(w2Key))

	t.Run("a-simple-wrapper-succeeds", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		multiWrapper, err := multi.NewPooledWrapper(ctx, w1)
		require.NoError(err)
		var encBlob *wrapping.BlobInfo

		encBlob, err = multiWrapper.Encrypt(context.Background(), []byte("foobar"), nil)
		require.NoError(err)
		assert.Equal("w1", encBlob.KeyInfo.KeyId)

		decVal, err := multiWrapper.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		decVal, err = w1.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		// Check retrieving the wrappers
		checkW1 := multiWrapper.WrapperForKeyId("w1")
		require.NotNil(checkW1)
		keyId, err := checkW1.KeyId(ctx)
		require.NoError(err)
		require.Equal("w1", keyId)

		// can't remove the encrypting wrapper
		_, err = multiWrapper.RemoveWrapper(ctx, "w1")
		require.Error(err)

		// check retrieving all the key ids
		assert.Equal(multiWrapper.AllKeyIds(), []string{"w1"})
	})

	t.Run("the-wrapper-can-be-extended", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		multiWrapper, err := multi.NewPooledWrapper(ctx, w1)
		require.NoError(err)
		encBlob, err := multiWrapper.Encrypt(context.Background(), []byte("foobar"), nil)
		require.NoError(err)
		assert.Equal("w1", encBlob.KeyInfo.KeyId)

		// Rotate the encryptor
		ok, err := multiWrapper.SetEncryptingWrapper(ctx, w2)
		require.NoError(err)
		require.True(ok)
		// Verify we can still decrypt the existing blob
		decVal, err := multiWrapper.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		// Now encrypt again and decrypt against the new base wrapper
		encBlob, err = multiWrapper.Encrypt(context.Background(), []byte("foobar"), nil)
		require.NoError(err)
		assert.Equal("w2", encBlob.KeyInfo.KeyId)

		decVal, err = multiWrapper.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		decVal, err = w2.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		// Check retrieving the wrappers
		checkW1 := multiWrapper.WrapperForKeyId("w1")
		require.NotNil(checkW1)
		keyId, err := checkW1.KeyId(ctx)
		require.NoError(err)
		require.Equal("w1", keyId)

		checkW2 := multiWrapper.WrapperForKeyId("w2")
		require.NotNil(checkW2)
		keyId, err = checkW2.KeyId(ctx)
		require.NoError(err)
		require.Equal("w2", keyId)

		// check retrieving all the key ids
		assert.Equal(multiWrapper.AllKeyIds(), []string{"w1", "w2"})

		ok, err = multiWrapper.RemoveWrapper(ctx, "w1")
		require.NoError(err)
		assert.True(ok)
		ok, err = multiWrapper.RemoveWrapper(ctx, "w1")
		require.NoError(err)
		assert.True(ok)
		// can't remove the encrypting wrapper
		_, err = multiWrapper.RemoveWrapper(ctx, "w2")
		require.Error(err)

		decVal, err = multiWrapper.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		// Check that w1 is no longer valid
		encBlob, err = w1.Encrypt(context.Background(), []byte("foobar"), nil)
		require.NoError(err)
		require.Equal("w1", encBlob.KeyInfo.KeyId)

		decVal, err = multiWrapper.Decrypt(context.Background(), encBlob, nil)
		require.Equal(multi.ErrKeyNotFound, err)
		assert.Nil(decVal)

		// check retrieving all the key ids
		assert.Equal(multiWrapper.AllKeyIds(), []string{"w2"})
	})

	t.Run("trying-to-get-a-nonexistent-wrapper-fails", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		multiWrapper, err := multi.NewPooledWrapper(ctx, w1)
		require.NoError(err)
		require.Nil(multiWrapper.WrapperForKeyId("w3"))
		ok, err := multiWrapper.RemoveWrapper(ctx, "w3")
		require.NoError(err)
		assert.True(ok) // never existed
	})

	t.Run("adding-a-duplicate-fails", func(t *testing.T) {
		t.Parallel()
		require := require.New(t)
		multiWrapper, err := multi.NewPooledWrapper(ctx, w1)
		require.NoError(err)
		ok, err := multiWrapper.AddWrapper(ctx, w1)
		require.NoError(err)
		require.False(ok)
	})

	t.Run("setting-a-duplicate-fails", func(t *testing.T) {
		t.Parallel()
		require := require.New(t)
		multiWrapper, err := multi.NewPooledWrapper(ctx, w1)
		require.NoError(err)
		ok, err := multiWrapper.SetEncryptingWrapper(ctx, w1)
		require.NoError(err)
		require.False(ok)
	})
}
