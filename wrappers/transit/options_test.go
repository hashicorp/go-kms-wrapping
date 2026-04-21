// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithMountPath", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withMountPath = ""
		assert.Equal(opts, testOpts)

		const with = "/test/path"
		opts, err = getOpts(WithMountPath(with))
		require.NoError(err)
		testOpts.withMountPath = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyName", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKeyName = ""
		assert.Equal(opts, testOpts)

		const with = "testKey"
		opts, err = getOpts(WithKeyName(with))
		require.NoError(err)
		testOpts.withKeyName = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDisableRenewal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withDisableRenewal = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		opts, err = getOpts(WithDisableRenewal(with))
		require.NoError(err)
		testOpts.withDisableRenewal = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithNamespace", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withNamespace = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		opts, err = getOpts(WithNamespace(with))
		require.NoError(err)
		testOpts.withNamespace = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAddress", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withAddress = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		opts, err = getOpts(WithAddress(with))
		require.NoError(err)
		testOpts.withAddress = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsCaCert", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsCaCert = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		opts, err = getOpts(WithTlsCaCert(with))
		require.NoError(err)
		testOpts.withTlsCaCert = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsCaPath", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsCaPath = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		opts, err = getOpts(WithTlsCaPath(with))
		require.NoError(err)
		testOpts.withTlsCaPath = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsClientCert", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsClientCert = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		opts, err = getOpts(WithTlsClientCert(with))
		require.NoError(err)
		testOpts.withTlsClientCert = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsClientKey", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsClientKey = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		opts, err = getOpts(WithTlsClientKey(with))
		require.NoError(err)
		testOpts.withTlsClientKey = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsServerName", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsServerName = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		opts, err = getOpts(WithTlsServerName(with))
		require.NoError(err)
		testOpts.withTlsServerName = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTlsSkipVerify", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsSkipVerify = false
		assert.Equal(opts, testOpts)

		opts, err = getOpts(WithTlsSkipVerify(true))
		require.NoError(err)
		testOpts.withTlsSkipVerify = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithToken", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withToken = ""
		assert.Equal(opts, testOpts)

		const with = "test"
		opts, err = getOpts(WithToken(with))
		require.NoError(err)
		testOpts.withToken = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLogger", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTlsServerName = ""
		assert.Equal(opts, testOpts)

		with := hclog.New(&hclog.LoggerOptions{
			Name:  "test-logger",
			Level: hclog.Error,
		})
		opts, err = getOpts(WithLogger(with))
		require.NoError(err)
		testOpts.withLogger = with
		assert.Equal(opts, testOpts)
	})
}
