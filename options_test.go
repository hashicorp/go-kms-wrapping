package wrapping

import (
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
	t.Run("WithWrapperOptions", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		strOpts := map[string]string{"foo": "bar"}
		opts, err := GetOpts(WithWrapperOptions(strOpts))
		require.NoError(err)
		require.NotNil(opts)
		assert.Equal(strOpts, opts.WithWrapperOptions)
	})
}
