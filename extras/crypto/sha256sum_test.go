// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/extras/crypto"
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

	t.Run("success-with-closer", func(t *testing.T) {
		c := writeCloser{
			b:      strings.Builder{},
			closed: false,
		}
		w, err := crypto.NewSha256SumWriter(testCtx, &c)
		require.NoError(t, err)

		hasher := sha256.New()
		_, err = hasher.Write(testBytes)
		require.NoError(t, err)
		_, err = hasher.Write(testBytes)
		require.NoError(t, err)
		wantSum := hasher.Sum(nil)

		assert, require := assert.New(t), require.New(t)
		_, err = w.Write(testBytes)
		require.NoError(err)
		_, err = w.WriteString(string(testBytes))
		require.NoError(err)
		sum, err := w.Sum(testCtx)
		require.NoError(err)
		assert.Equal(wantSum, sum)
		require.NoError(w.Close())

		require.True(c.closed)
	})
}

type writeCloser struct {
	b      strings.Builder
	closed bool
}

func (w *writeCloser) Write(b []byte) (int, error) {
	return w.b.Write(b)
}

func (w *writeCloser) Close() error {
	w.closed = true
	return nil
}

func TestSha256SumReader_Sum(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testBytes := []byte("test-bytes")
	tests := []struct {
		name            string
		data            []byte
		sumReader       *crypto.Sha256SumReader
		opt             []wrapping.Option
		wantSum         []byte
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "success",
			data: testBytes,
			sumReader: func() *crypto.Sha256SumReader {
				b := bytes.NewBuffer(testBytes)
				w, err := crypto.NewSha256SumReader(testCtx, b)
				require.NoError(t, err)
				return w
			}(),
			wantSum: func() []byte {
				hasher := sha256.New()
				_, err := hasher.Write(testBytes)
				require.NoError(t, err)
				return hasher.Sum(nil)
			}(),
		},
		{
			name: "success-with-hex-encoding",
			data: testBytes,
			sumReader: func() *crypto.Sha256SumReader {
				b := bytes.NewBuffer(testBytes)
				w, err := crypto.NewSha256SumReader(testCtx, b)
				require.NoError(t, err)
				return w
			}(),
			opt: []wrapping.Option{crypto.WithHexEncoding(true)},
			wantSum: func() []byte {
				hasher := sha256.New()
				_, err := hasher.Write(testBytes)
				require.NoError(t, err)
				h := hasher.Sum(nil)
				return []byte(hex.EncodeToString(h[:]))
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			buf := make([]byte, len(tc.data))
			_, err := tc.sumReader.Read(buf)
			require.NoError(err)
			require.Equal(buf, tc.data)
			sum, err := tc.sumReader.Sum(testCtx, tc.opt...)
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
			require.NoError(tc.sumReader.Close())
		})
	}

	t.Run("success-with-closer", func(t *testing.T) {
		c := readCloser{
			b:      bytes.NewBuffer(testBytes),
			closed: false,
		}
		w, err := crypto.NewSha256SumReader(testCtx, &c)
		require.NoError(t, err)

		hasher := sha256.New()
		_, err = hasher.Write(testBytes)
		require.NoError(t, err)
		wantSum := hasher.Sum(nil)

		assert, require := assert.New(t), require.New(t)
		buf := make([]byte, len(testBytes))
		_, err = w.Read(buf)
		require.NoError(err)
		require.Equal(buf, testBytes)
		sum, err := w.Sum(testCtx)
		require.NoError(err)
		assert.Equal(wantSum, sum)
		require.NoError(w.Close())

		require.True(c.closed)
	})
}

type readCloser struct {
	b      *bytes.Buffer
	closed bool
}

func (w *readCloser) Read(b []byte) (int, error) {
	return w.b.Read(b)
}

func (w *readCloser) Close() error {
	w.closed = true
	return nil
}
