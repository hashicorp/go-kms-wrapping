package plugin

import (
	"io/fs"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	gp "github.com/hashicorp/go-plugin"
	"github.com/stretchr/testify/require"
)

// TestPlugin is a function to return a plugin wrapper and a cleanup function to
// call when the test is done. This will read the original plugin bytes, write
// them out to a new location, and execute it, handing back the interface.
//
// Parameters:
//
// * pluginLoc: The binary location of the plugin
// * root: The wrapper
// * handshakeConfig: The shared handshake config used by the plugin and the client here

func TestPlugin(
	t *testing.T,
	pluginLoc string,
	inWrapper wrapping.Wrapper,
	handshakeConfig gp.HandshakeConfig) (pluginWrapper wrapping.Wrapper, cleanup func()) {
	t.Helper()
	require := require.New(t)

	require.NotEmpty(pluginLoc, "plugin location cannot be empty")

	tmpDir, err := ioutil.TempDir("", "*")
	require.NoError(err)

	// Set cleanup function
	cleanup = func() {
		require.NoError(os.RemoveAll(tmpDir))
	}

	pluginBytes, err := ioutil.ReadFile(pluginLoc)
	require.NoError(err)

	pluginPath := filepath.Join(tmpDir, "plugin")
	require.NoError(ioutil.WriteFile(pluginPath, pluginBytes, fs.FileMode(0700)))

	client := gp.NewClient(&gp.ClientConfig{
		HandshakeConfig: handshakeConfig,
		VersionedPlugins: map[int]gp.PluginSet{
			1: {"wrapping": NewWrapper(inWrapper)},
		},
		Cmd: exec.Command(pluginPath),
		AllowedProtocols: []gp.Protocol{
			gp.ProtocolGRPC,
		},
	})
	defer client.Kill()

	rpcClient, err := client.Client()
	require.NoError(err)

	raw, err := rpcClient.Dispense("wrapping")
	require.NoError(err)

	var ok bool
	pluginWrapper, ok = raw.(wrapping.Wrapper)
	require.True(ok)
	require.NotNil(pluginWrapper)

	return
}
