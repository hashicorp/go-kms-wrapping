package plugin

import (
	context "context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAeadPluginWrapper(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	pluginPath := os.Getenv("PLUGIN_PATH")
	if pluginPath == "" {
		t.Skipf("skipping plugin test as no PLUGIN_PATH specified")
	}

	wrapper, cleanup := TestPlugin(t, pluginPath)

	require.NotNil(cleanup)
	defer cleanup()

	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}

	_, err = wrapper.SetConfig(
		context.Background(),
		wrapping.WithKeyId("root"),
		wrapping.WithConfigMap(map[string]string{
			"key": base64.StdEncoding.EncodeToString(rootKey),
		}),
	)
	require.NoError(err)

	keyId, err := wrapper.KeyId(ctx)
	require.NoError(err)
	require.Equal(keyId, "root")

	encBlob, err := wrapper.Encrypt(context.Background(), []byte("foobar"))
	require.NoError(err)

	// Sanity check
	decVal, err := wrapper.Decrypt(context.Background(), encBlob)
	require.NoError(err)
	require.Equal("foobar", string(decVal))
}

func TestInterfaceWrapper(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	pluginPath := os.Getenv("PLUGIN_PATH")
	if pluginPath == "" {
		t.Skipf("skipping plugin test as no PLUGIN_PATH specified")
	}

	var ok bool

	wrapper, wrapperCleanup := TestPlugin(t, filepath.Join(pluginPath, "wrapperplugin"))
	if wrapperCleanup != nil {
		t.Cleanup(wrapperCleanup)
	}
	keyId, err := wrapper.KeyId(ctx)
	assert.NoError(err)
	assert.Equal(keyId, "static-key")

	ifWrapper, ok := wrapper.(wrapping.InitFinalizer)
	require.True(ok)
	err = ifWrapper.Init(ctx)
	require.Error(err)
	assert.True(errors.Is(err, wrapping.ErrFunctionNotImplemented))
	err = ifWrapper.Finalize(ctx)
	require.Error(err)
	assert.True(errors.Is(err, wrapping.ErrFunctionNotImplemented))

	hmacWrapper, ok := wrapper.(wrapping.HmacComputer)
	require.True(ok)
	keyId, err = hmacWrapper.HmacKeyId(ctx)
	require.Error(err)
	assert.Empty(keyId)
	assert.True(errors.Is(err, wrapping.ErrFunctionNotImplemented))
}

func TestInterfaceAll(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	pluginPath := os.Getenv("PLUGIN_PATH")
	if pluginPath == "" {
		t.Skipf("skipping plugin test as no PLUGIN_PATH specified")
	}

	var ok bool
	// Now get one that does and validate it
	wrapper, wrapperCleanup := TestPlugin(t, filepath.Join(pluginPath, "initfinalizerhmaccomputerplugin"))
	if wrapperCleanup != nil {
		t.Cleanup(wrapperCleanup)
	}
	keyId, err := wrapper.KeyId(ctx)
	assert.NoError(err)
	assert.Equal(keyId, "static-key")

	ifWrapper, ok := wrapper.(wrapping.InitFinalizer)
	require.True(ok)
	require.NoError(ifWrapper.Init(ctx))
	require.NoError(ifWrapper.Finalize(ctx))

	hmacWrapper, ok := wrapper.(wrapping.HmacComputer)
	require.True(ok)
	keyId, err = hmacWrapper.HmacKeyId(ctx)
	require.NoError(err)
	assert.Equal(keyId, "hmac-key")
}
