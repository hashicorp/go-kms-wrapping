// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package wrapping

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("nil", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := GetOpts(nil)
		assert.NoError(err)
		assert.NotNil(opts)
	})
	t.Run("wrong-type", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := GetOpts(Option(func() interface{} {
			return nil
		}))
		assert.Error(err)
		assert.Nil(opts)
	})
	t.Run("right-type", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := GetOpts(Option(func() interface{} {
			return OptionFunc(func(*Options) error {
				return nil
			})
		}))
		assert.NoError(err)
		assert.NotNil(opts)
	})
	t.Run("WithAad", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts(WithAad([]byte("foo")))
		require.NoError(err)
		require.NotNil(opts)
		assert.Equal([]byte("foo"), opts.WithAad)
	})
	t.Run("WithKeyId", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts(WithKeyId("bar"))
		require.NoError(err)
		require.NotNil(opts)
		assert.Equal("bar", opts.WithKeyId)
	})
	t.Run("WithConfigMap", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		strOpts := map[string]string{"foo": "bar"}
		opts, err := GetOpts(WithConfigMap(strOpts))
		require.NoError(err)
		require.NotNil(opts)
		assert.Equal(strOpts, opts.WithConfigMap)
	})
	t.Run("WithKeyPurposes", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts(WithKeyPurposes(KeyPurpose_Sign))
		require.NoError(err)
		require.NotNil(opts)
		assert.Equal([]KeyPurpose{KeyPurpose_Sign}, opts.WithKeyPurposes)
	})
	t.Run("WithKeyType", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts(WithKeyType(KeyType_Ed25519))
		require.NoError(err)
		require.NotNil(opts)
		assert.Equal(KeyType_Ed25519, opts.WithKeyType)
	})
	t.Run("WithRandomBytes", func(t *testing.T) {
		testBytes := []byte("test")
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts(WithRandomBytes(testBytes))
		require.NoError(err)
		require.NotNil(opts)
		assert.Equal(testBytes, opts.WithRandomBytes)
	})
	t.Run("WithKeyEncoding", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts(WithKeyEncoding(KeyEncoding_Bytes))
		require.NoError(err)
		require.NotNil(opts)
		assert.Equal(KeyEncoding_Bytes, opts.WithKeyEncoding)
	})
	t.Run("WithWrappedKeyEncoding", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts(WithWrappedKeyEncoding(KeyEncoding_Bytes))
		require.NoError(err)
		require.NotNil(opts)
		assert.Equal(KeyEncoding_Bytes, opts.WithWrappedKeyEncoding)
	})
	t.Run("WithDisallowEnvVars", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts(WithDisallowEnvVars(true))
		require.NoError(err)
		require.NotNil(opts)
		assert.True(opts.WithDisallowEnvVars)
	})
}

func testOptionWithError(t *testing.T) Option {
	t.Helper()
	return func() interface{} {
		return OptionFunc(func(o *Options) error {
			return errors.New("option error")
		})
	}
}

func TestParsePaths(t *testing.T) {
	type options struct {
		optionA string
		optionB string
	}

	test := options{
		optionA: "Hello, World!",
		optionB: "file://test-fixtures/secret.txt",
	}
	if err := ParsePaths(&test.optionA, &test.optionB); err != nil {
		t.Fatal(err)
	}
	if test.optionB != "Top Secret" {
		t.Fatalf("expected TopSecret, got %s", test.optionB)
	}

	// Test nil handling
	test = options{
		optionA: "file://test-fixtures/secret.txt",
	}
	if err := ParsePaths(nil, &test.optionA, nil); err != nil {
		t.Fatal(err)
	}
	if test.optionA != "Top Secret" {
		t.Fatalf("expected TopSecret, got %s", test.optionB)
	}

	// Test errors and error atomicity
	test = options{
		optionA: "file://test-fixtures/secret.txt",
		optionB: "file://test-fixtures/missing.txt",
	}
	if err := ParsePaths(&test.optionA, &test.optionB); err == nil {
		t.Fatal("expected error but didn't get one")
	}

	if test.optionA != "file://test-fixtures/secret.txt" {
		t.Fatalf("optionA was overwritten despite encountering an error")
	}
}
