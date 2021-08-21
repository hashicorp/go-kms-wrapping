package plugin

import (
	context "context"
	"crypto/rand"
	"encoding/base64"
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
		wrapping.WithWrapperOptions(map[string]string{
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

func TestInterfaces(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	pluginPath := os.Getenv("PLUGIN_PATH")
	if pluginPath == "" {
		t.Skipf("skipping plugin test as no PLUGIN_PATH specified")
	}

	var ok bool

	// First get a normal wrapper and ensure it doesn't satisfy InitFinalizer
	wrapper, wrapperCleanup := TestPlugin(t, filepath.Join(pluginPath, "wrapperplugin"))
	if wrapperCleanup != nil {
		defer wrapperCleanup()
	}
	keyId, err := wrapper.KeyId(ctx)
	assert.NoError(err)
	assert.Equal(keyId, "static-key")
	_, ok = wrapper.(wrapping.InitFinalizer)
	assert.False(ok)

	// Now get a wrapper satisfying InitFinalizer and ensure it does
	initFinalizer, initFinalizerCleanup := TestPlugin(t, filepath.Join(pluginPath, "initfinalizerplugin"), WithInitFinalizeInterface(true))
	if initFinalizerCleanup != nil {
		defer initFinalizerCleanup()
	}
	keyId, err = initFinalizer.KeyId(ctx)
	assert.NoError(err)
	assert.Equal(keyId, "static-key")

	ifWrapper, ok := initFinalizer.(wrapping.InitFinalizer)
	require.True(ok)
	require.NoError(ifWrapper.Init(ctx))
	require.NoError(ifWrapper.Finalize(ctx))
}
