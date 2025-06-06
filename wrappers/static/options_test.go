// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package static

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithPreviousKey", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withPreviousKey = ""
		assert.Equal(opts, testOpts)

		const with = "/test/path"
		opts, err = getOpts(WithPreviousKey(with))
		require.NoError(err)
		testOpts.withPreviousKey = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithCurrentKey", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withCurrentKey = ""
		assert.Equal(opts, testOpts)

		const with = "/test/path"
		opts, err = getOpts(WithCurrentKey(with))
		require.NoError(err)
		testOpts.withCurrentKey = with
		assert.Equal(opts, testOpts)
	})
}
