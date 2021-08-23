package plugin

import (
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
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

func TestPlugin(
	t *testing.T,
	pluginLoc string,
	opt ...Option) (pluginWrapper wrapping.Wrapper, cleanup func()) {
	t.Helper()
	require := require.New(t)

	opts, err := getOpts(opt...)
	require.NoError(err)

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

	client, err := NewWrapperClient(pluginPath, opt...)
	require.NoError(err)

	// Now that we have a client, ensure it's killed at cleanup time
	origCleanup := cleanup
	cleanup = func() {
		defer client.Kill()
		origCleanup()
	}

	rpcClient, err := client.Client()
	require.NoError(err)

	raw, err := rpcClient.Dispense("wrapping")
	require.NoError(err)

	var ok bool
	pluginWrapper, ok = raw.(wrapping.Wrapper)
	require.True(ok)
	if opts.withInitFinalizerInterface {
		_, ok := raw.(wrapping.InitFinalizer)
		require.True(ok)
	}
	if opts.withHmacComputerInterface {
		_, ok := raw.(wrapping.HmacComputer)
		require.True(ok)
	}
	require.NotNil(pluginWrapper)

	return
}
