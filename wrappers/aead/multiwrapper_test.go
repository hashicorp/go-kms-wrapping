package aead_test

import (
	"context"
	"crypto/rand"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/multiwrapper"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiWrapper(t *testing.T) {
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

	multi := multiwrapper.NewMultiWrapper(ctx, w1)
	var encBlob *wrapping.BlobInfo

	// Start with one and ensure encrypt/decrypt
	{
		encBlob, err = multi.Encrypt(context.Background(), []byte("foobar"), nil)
		require.NoError(err)
		assert.Equal("w1", encBlob.KeyInfo.KeyId)

		decVal, err := multi.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		decVal, err = w1.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))
	}

	// Rotate the encryptor
	require.True(multi.SetEncryptingWrapper(ctx, w2))
	{
		// Verify we can still decrypt the existing blob
		decVal, err := multi.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		// Now encrypt again and decrypt against the new base wrapper
		encBlob, err = multi.Encrypt(context.Background(), []byte("foobar"), nil)
		require.NoError(err)
		assert.Equal("w2", encBlob.KeyInfo.KeyId)

		decVal, err = multi.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		decVal, err = w2.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))
	}

	// Check retriving the wrappers
	checkW1 := multi.WrapperForKeyId("w1")
	require.NotNil(checkW1)
	require.Equal("w1", checkW1.KeyId(ctx))

	checkW2 := multi.WrapperForKeyId("w2")
	require.NotNil(checkW2)
	require.Equal("w2", checkW2.KeyId(ctx))

	require.Nil(multi.WrapperForKeyId("w3"))

	// Check removing a wrapper, and not removing the base wrapper
	assert.True(multi.RemoveWrapper(ctx, "w1"))
	assert.True(multi.RemoveWrapper(ctx, "w1"))  // returns false after removal
	assert.False(multi.RemoveWrapper(ctx, "w2")) // base
	assert.True(multi.RemoveWrapper(ctx, "w3"))  // never existed
	{
		decVal, err := multi.Decrypt(context.Background(), encBlob, nil)
		require.NoError(err)
		assert.Equal("foobar", string(decVal))

		// Check that w1 is no longer valid
		encBlob, err = w1.Encrypt(context.Background(), []byte("foobar"), nil)
		require.NoError(err)
		require.Equal("w1", encBlob.KeyInfo.KeyId)

		decVal, err = multi.Decrypt(context.Background(), encBlob, nil)
		require.Equal(multiwrapper.ErrKeyNotFound, err)
		assert.Nil(decVal)
	}
}
