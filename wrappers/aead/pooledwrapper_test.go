package aead_test

import (
	"context"
	"crypto/rand"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/multi"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPooledWrapper(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()

	w1Key := make([]byte, 32)
	n, err := rand.Read(w1Key)
	require.NoError(err)
	require.Equal(n, 32)

	w1 := aead.NewWrapper()
	_, err = w1.SetConfig(ctx, wrapping.WithKeyId("w1"))
	require.NoError(err)
	require.NoError(w1.SetAesGcmKeyBytes(w1Key))

	w2Key := make([]byte, 32)
	n, err = rand.Read(w2Key)
	require.NoError(err)
	require.Equal(n, 32)

	w2 := aead.NewWrapper()
	_, err = w2.SetConfig(ctx, wrapping.WithKeyId("w2"))
	require.NoError(err)
	require.NoError(w2.SetAesGcmKeyBytes(w2Key))

	multiWrapper, err := multi.NewPooledWrapper(ctx, w1)
	require.NoError(err)
	var encBlob *wrapping.BlobInfo

	// Start with one and ensure encrypt/decrypt
	{
		encBlob, err = multiWrapper.Encrypt(context.Background(), []byte("foobar"), nil)
		require.NoError(err)
		assert.Equal("w1", encBlob.KeyInfo.KeyId)

		decVal, err := multiWrapper.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		decVal, err = w1.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))
	}

	// Rotate the encryptor
	require.True(multiWrapper.SetEncryptingWrapper(ctx, w2))
	{
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
	}

	// Check retriving the wrappers
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

	require.Nil(multiWrapper.WrapperForKeyId("w3"))

	// Check removing a wrapper, and not removing the base wrapper
	assert.True(multiWrapper.RemoveWrapper(ctx, "w1"))
	assert.True(multiWrapper.RemoveWrapper(ctx, "w1"))  // returns false after removal
	assert.False(multiWrapper.RemoveWrapper(ctx, "w2")) // base
	assert.True(multiWrapper.RemoveWrapper(ctx, "w3"))  // never existed
	{
		decVal, err := multiWrapper.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		// Check that w1 is no longer valid
		encBlob, err = w1.Encrypt(context.Background(), []byte("foobar"), nil)
		require.NoError(err)
		require.Equal("w1", encBlob.KeyInfo.KeyId)

		decVal, err = multiWrapper.Decrypt(context.Background(), encBlob, nil)
		require.Equal(multi.ErrKeyNotFound, err)
		assert.Nil(decVal)
	}
}
