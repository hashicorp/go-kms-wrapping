package kms

import (
	"reflect"
	"runtime"
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
		testOpts.withErrorsMatching = nil
		opts.withErrorsMatching = nil
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(-1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = -1
		testOpts.withErrorsMatching = nil
		opts.withErrorsMatching = nil
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = 1
		testOpts.withErrorsMatching = nil
		opts.withErrorsMatching = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRootWrapper", func(t *testing.T) {
		testWrapper := wrapping.NewTestWrapper([]byte(DefaultWrapperSecret))
		assert := assert.New(t)
		opts := getOpts(WithRootWrapper(testWrapper))
		testOpts := getDefaultOptions()
		testOpts.withRootWrapper = testWrapper
		testOpts.withErrorsMatching = nil
		opts.withErrorsMatching = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRepository", func(t *testing.T) {
		assert := assert.New(t)
		db, _ := TestDb(t)
		testRepo := TestRepo(t, db)

		opts := getOpts(WithRepository(testRepo))
		testOpts := getDefaultOptions()
		testOpts.withRepository = testRepo
		testOpts.withErrorsMatching = nil
		opts.withErrorsMatching = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithKeyId("id"))
		testOpts := getDefaultOptions()
		testOpts.withKeyId = "id"
		testOpts.withErrorsMatching = nil
		opts.withErrorsMatching = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOrderByVersion", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithOrderByVersion(DescendingOrderBy))
		testOpts := getDefaultOptions()
		testOpts.withOrderByVersion = DescendingOrderBy
		testOpts.withErrorsMatching = nil
		opts.withErrorsMatching = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRetryErrorsMatching", func(t *testing.T) {
		assert := assert.New(t)

		// testing the default first...
		opts := getOpts()
		// using this pattern to test for equality: https://github.com/stretchr/testify/issues/182#issuecomment-495359313
		funcName1 := runtime.FuncForPC(reflect.ValueOf(noOpErrorMatchingFn).Pointer()).Name()
		funcName2 := runtime.FuncForPC(reflect.ValueOf(opts.withErrorsMatching).Pointer()).Name()
		assert.Equal(funcName1, funcName2)

		// now, we'll test an optional override
		fn := func(error) bool { return true }
		opts = getOpts(WithRetryErrorsMatching(fn))
		funcName1 = runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
		funcName2 = runtime.FuncForPC(reflect.ValueOf(opts.withErrorsMatching).Pointer()).Name()
		assert.Equal(funcName1, funcName2)
	})
	t.Run("WithRetryCount", func(t *testing.T) {
		const cnt = 1000
		assert := assert.New(t)
		opts := getOpts(WithRetryCount(cnt))
		testOpts := getDefaultOptions()
		testOpts.withRetryCnt = cnt
		testOpts.withErrorsMatching = nil
		opts.withErrorsMatching = nil
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPurpose", func(t *testing.T) {
		const purpose = "test-purpose"
		assert := assert.New(t)
		opts := getOpts(WithPurpose(purpose))
		testOpts := getDefaultOptions()
		testOpts.withPurpose = purpose
		testOpts.withErrorsMatching = nil
		opts.withErrorsMatching = nil
		assert.Equal(opts, testOpts)
	})
}
