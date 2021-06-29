package aead

import (
	"context"
	"crypto/rand"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestShamirVsAEAD(t *testing.T) {
	a := NewWrapper()
	require.Equal(t, a.Type(), wrapping.WrapperTypeAead)

	s := NewShamirWrapper()
	require.Equal(t, s.Type(), wrapping.WrapperTypeShamir)
}

func TestWrapperAndDerivedWrapper(t *testing.T) {
	require := require.New(t)

	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	root := NewWrapper()
	_, err = root.SetConfig(context.Background(), wrapping.WithKeyId("root"))
	require.NoError(err)
	require.NoError(root.SetAesGcmKeyBytes(rootKey))
	require.Equal(root.KeyId(), "root")

	encBlob, err := root.Encrypt(context.Background(), []byte("foobar"))
	require.NoError(err)

	// Sanity check
	decVal, err := root.Decrypt(context.Background(), encBlob)
	require.NoError(err)
	require.Equal("foobar", string(decVal))

	opts, err := structpb.NewStruct(map[string]interface{}{
		"salt": []byte("zip"),
		"info": []byte("zap"),
	})
	require.NoError(err)
	sub, err := root.NewDerivedWrapper(
		wrapping.WithKeyId("sub"),
		wrapping.WithWrapperOptions(opts))
	require.NoError(err)
	require.Equal("sub", sub.KeyId())

	// This should fail as it should be a different key
	decVal, err = sub.Decrypt(context.Background(), encBlob)
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

	// Ensure that deriving a second subkey with the same params works
	opts, err = structpb.NewStruct(map[string]interface{}{
		"salt": []byte("zip"),
		"info": []byte("zap"),
	})
	require.NoError(err)
	sub2, err := root.NewDerivedWrapper(
		wrapping.WithKeyId("sub2"),
		wrapping.WithWrapperOptions(opts),
	)
	require.NoError(err)
	require.Equal("sub2", sub2.KeyId())

	subDecVal, err = sub2.Decrypt(context.Background(), subEncBlob)
	require.NoError(err)
	require.Equal("foobar", string(subDecVal))
	require.NotNil(subDecVal)

	// Ensure that a subkey with different params doesn't work
	opts, err = structpb.NewStruct(map[string]interface{}{
		"salt": []byte("zap"),
		"info": []byte("zip"),
	})
	require.NoError(err)
	subBad, err := root.NewDerivedWrapper(
		wrapping.WithKeyId("sub2"),
		wrapping.WithWrapperOptions(opts),
	)
	require.NoError(err)
	subDecVal, err = subBad.Decrypt(context.Background(), subEncBlob)
	require.Error(err)
	require.Nil(subDecVal)
}
