// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
		opt             []wrapping.Option
		wantSum         []byte
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "string",
			r:    strings.NewReader(testString),
			wantSum: func() []byte {
				hasher := sha256.New()
				_, err := hasher.Write([]byte(testString))
				require.NoError(t, err)
				return hasher.Sum(nil)
			}(),
		},
		{
			name:    "string",
			r:       strings.NewReader(testString),
			opt:     []wrapping.Option{crypto.WithHexEncoding(true)},
			wantSum: []byte(testSum),
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
			opt:     []wrapping.Option{crypto.WithHexEncoding(true)},
			wantSum: []byte(testSum),
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
			sum, err := crypto.Sha256Sum(testCtx, tc.r, tc.opt...)
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

func TestSha256SumWriter_Sum(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testBytes := []byte("test-bytes")
	tests := []struct {
		name            string
		data            []byte
		sumWriter       *crypto.Sha256SumWriter
		opt             []wrapping.Option
		wantSum         []byte
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "success",
			data: testBytes,
			sumWriter: func() *crypto.Sha256SumWriter {
				var b strings.Builder
				w, err := crypto.NewSha256SumWriter(testCtx, &b)
				require.NoError(t, err)
				return w
			}(),
			wantSum: func() []byte {
				hasher := sha256.New()
				_, err := hasher.Write(testBytes)
				require.NoError(t, err)
				_, err = hasher.Write(testBytes)
				require.NoError(t, err)
				return hasher.Sum(nil)
			}(),
		},
		{
			name: "success-with-hex-encoding",
			data: testBytes,
			sumWriter: func() *crypto.Sha256SumWriter {
				var b strings.Builder
				w, err := crypto.NewSha256SumWriter(testCtx, &b)
				require.NoError(t, err)
				return w
			}(),
			opt: []wrapping.Option{crypto.WithHexEncoding(true)},
			wantSum: func() []byte {
				hasher := sha256.New()
				_, err := hasher.Write(testBytes)
				require.NoError(t, err)
				_, err = hasher.Write(testBytes)
				require.NoError(t, err)
				h := hasher.Sum(nil)
				return []byte(hex.EncodeToString(h[:]))
			}(),
		},
		{
			name: "success-with-closer",
			data: testBytes,
			sumWriter: func() *crypto.Sha256SumWriter {
				c := closer{
					b: strings.Builder{},
				}
				w, err := crypto.NewSha256SumWriter(testCtx, &c)
				require.NoError(t, err)
				return w
			}(),
			wantSum: func() []byte {
				hasher := sha256.New()
				_, err := hasher.Write(testBytes)
				require.NoError(t, err)
				_, err = hasher.Write(testBytes)
				require.NoError(t, err)
				return hasher.Sum(nil)
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			_, err := tc.sumWriter.Write(tc.data)
			require.NoError(err)
			_, err = tc.sumWriter.WriteString(string(tc.data))
			require.NoError(err)
			sum, err := tc.sumWriter.Sum(testCtx, tc.opt...)
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
			require.NoError(tc.sumWriter.Close())
		})
	}
}

type closer struct {
	b strings.Builder
}

func (w *closer) Write(b []byte) (int, error) {
	return w.b.Write(b)
}

func (*closer) Close() error {
	return nil
}
