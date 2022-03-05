package wrapping

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnvelope(t *testing.T) {
	require := require.New(t)
	input := []byte("test")

	env, err := EnvelopeEncrypt(input)
	require.NoError(err)

	output, err := EnvelopeDecrypt(env)
	require.NoError(err)

	require.Equal(input, output)
}

func TestEnvelopeAad(t *testing.T) {
	require := require.New(t)
	input := []byte("test")

	env, err := EnvelopeEncrypt(input, WithAad([]byte("foo")))
	require.NoError(err)

	output, err := EnvelopeDecrypt(env)
	require.Error(err)
	require.Nil(output)

	output, err = EnvelopeDecrypt(env, WithAad([]byte("foo")))
	require.NoError(err)

	require.Equal(input, output)
}
