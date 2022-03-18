package kms

import (
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithLimit", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withLimit = 0
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(-1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = -1
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = 1
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRootWrapper", func(t *testing.T) {
		testWrapper := wrapping.NewTestWrapper([]byte("secret"))
		assert := assert.New(t)
		opts := getOpts(WithRootWrapper(testWrapper))
		testOpts := getDefaultOptions()
		testOpts.withRootWrapper = testWrapper
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRepository", func(t *testing.T) {
		assert := assert.New(t)
		db, _ := TestDb(t)
		testRepo := TestRepo(t, db)

		opts := getOpts(WithRepository(testRepo))
		testOpts := getDefaultOptions()
		testOpts.withRepository = testRepo
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithKeyId("id"))
		testOpts := getDefaultOptions()
		testOpts.withKeyId = "id"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOrderByVersion", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithOrderByVersion(DescendingOrderBy))
		testOpts := getDefaultOptions()
		testOpts.withOrderByVersion = DescendingOrderBy
		assert.Equal(opts, testOpts)
	})
}
