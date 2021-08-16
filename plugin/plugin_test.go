package plugin

import (
	context "context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestAeadPluginWrapper(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	pluginPath := os.Getenv("PLUGIN_PATH")
	if pluginPath == "" {
		t.Skipf("skipping plugin test as no PLUGIN_PATH specified")
	}

	wrapper, cleanup := TestPlugin(t, pluginPath, HandshakeConfig)

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

	setConfigOpts, err := structpb.NewStruct(map[string]interface{}{
		"key": base64.StdEncoding.EncodeToString(rootKey),
	})
	require.NoError(err)
	_, err = wrapper.SetConfig(
		context.Background(),
		wrapping.WithKeyId("root"),
		wrapping.WithWrapperOptions(setConfigOpts),
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
