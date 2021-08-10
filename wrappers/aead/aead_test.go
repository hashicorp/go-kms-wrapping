package aead

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"testing"

	gkwp "github.com/hashicorp/go-kms-wrapping/plugin/v2"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
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

func TestDirectWrapper(t *testing.T) {
	root := NewWrapper()
	encBlob := testWrapper(t, root)
	testDerivation(t, root, encBlob)
}

func TestPluginWrapper(t *testing.T) {
	require := require.New(t)

	pluginPath := os.Getenv("PLUGIN_PATH")
	if pluginPath == "" {
		t.Skipf("skipping plugin test as no PLUGIN_PATH specified")
	}

	wrapper, cleanup := gkwp.TestPlugin(t, pluginPath, gkwp.HandshakeConfig)

	require.NotNil(cleanup)
	defer cleanup()

	require.NotNil(wrapper)
	testWrapper(t, wrapper)
}

func testWrapper(t *testing.T, root wrapping.Wrapper) *wrapping.BlobInfo {
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

	setConfigOpts, err := structpb.NewStruct(map[string]interface{}{
		"key": base64.StdEncoding.EncodeToString(rootKey),
	})
	require.NoError(err)
	_, err = root.SetConfig(
		context.Background(),
		wrapping.WithKeyId("root"),
		wrapping.WithWrapperOptions(setConfigOpts),
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
	opts, err := structpb.NewStruct(map[string]interface{}{
		"salt": []byte("zip"),
		"info": []byte("zap"),
	})
	require.NoError(err)
	sub, err := root.NewDerivedWrapper(
		wrapping.WithKeyId("sub"),
		wrapping.WithWrapperOptions(opts))
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
