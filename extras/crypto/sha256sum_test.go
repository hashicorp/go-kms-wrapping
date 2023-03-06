package crypto_test

import (
	"context"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSha256Sum(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()

	// testSum created via: echo -n "test-string" | sha256sum
	const (
		testSum    = "ffe65f1d98fafedea3514adc956c8ada5980c6c5d2552fd61f48401aefd5c00e"
		testString = "test-string"
	)

	tests := []struct {
		name            string
		r               io.Reader
		wantSum         string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:    "string",
			r:       strings.NewReader(testString),
			wantSum: testSum,
		},
		{
			name: "file",
			r: func() io.Reader {
				f, err := ioutil.TempFile(t.TempDir(), "tmp")
				require.NoError(t, err)

				l, err := f.WriteString(testString)
				require.NoError(t, err)
				require.Equal(t, l, len(testString))

				f.Close()

				f, err = os.Open(f.Name())
				require.NoError(t, err)
				return f
			}(),
			wantSum: testSum,
		},
		{
			name:            "missing-reader",
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing reader",
		},
		{
			name: "closed-reader",
			r: func() io.Reader {
				f, err := ioutil.TempFile(t.TempDir(), "tmp")
				require.NoError(t, err)
				f.Close()
				return f
			}(),
			wantErr:         true,
			wantErrIs:       os.ErrClosed,
			wantErrContains: "file already closed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			sum, err := crypto.Sha256Sum(testCtx, tc.r)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(sum)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.wantSum, sum)
		})
	}
}
