// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"context"
	"crypto/sha256"
	"io"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/aead"
	"github.com/openbao/go-kms-wrapping/v2/extras/crypto"
	"github.com/openbao/go-kms-wrapping/v2/extras/multi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestNewDerivedReader(t *testing.T) {
	testWrapper := wrapping.NewTestWrapper([]byte("secret"))
	pooledWrapper := aead.TestPooledWrapper(t)
	aeadWrapper := aead.TestWrapper(t)
	ctx := context.Background()

	type args struct {
		wrapper  wrapping.Wrapper
		lenLimit int64
		opt      []wrapping.Option
	}
	tests := []struct {
		name            string
		args            args
		want            *io.LimitedReader
		wantErr         bool
		wantErrCode     error
		wantErrContains string
	}{
		{
			name: "valid-aead-with-salt",
			args: args{
				wrapper:  aeadWrapper,
				lenLimit: 32,
				opt:      []wrapping.Option{crypto.WithSalt([]byte("salt"))},
			},
			want: func() *io.LimitedReader {
				b, err := aeadWrapper.(*aead.Wrapper).KeyBytes(ctx)
				require.NoError(t, err)
				r := &io.LimitedReader{
					R: hkdf.New(sha256.New, b, []byte("salt"), nil),
					N: 32,
				}
				return r
			}(),
		},
		{
			name: "valid-aead-with-salt-info",
			args: args{
				wrapper:  aeadWrapper,
				lenLimit: 32,
				opt:      []wrapping.Option{crypto.WithInfo([]byte("info")), crypto.WithSalt([]byte("salt"))},
			},
			want: func() *io.LimitedReader {
				b, err := aeadWrapper.(*aead.Wrapper).KeyBytes(ctx)
				require.NoError(t, err)
				r := &io.LimitedReader{
					R: hkdf.New(sha256.New, b, []byte("salt"), []byte("info")),
					N: 32,
				}
				return r
			}(),
		},
		{
			name: "valid-with-salt",
			args: args{
				wrapper:  testWrapper,
				lenLimit: 32,
				opt:      []wrapping.Option{crypto.WithSalt([]byte("salt"))},
			},
			want: func() *io.LimitedReader {
				b, err := testWrapper.KeyBytes(ctx)
				require.NoError(t, err)
				r := &io.LimitedReader{
					R: hkdf.New(sha256.New, b, []byte("salt"), nil),
					N: 32,
				}
				return r
			}(),
		},
		{
			name: "valid-with-salt-info",
			args: args{
				wrapper:  testWrapper,
				lenLimit: 32,
				opt:      []wrapping.Option{crypto.WithInfo([]byte("info")), crypto.WithSalt([]byte("salt"))},
			},
			want: func() *io.LimitedReader {
				b, err := testWrapper.KeyBytes(ctx)
				require.NoError(t, err)
				r := &io.LimitedReader{
					R: hkdf.New(sha256.New, b, []byte("salt"), []byte("info")),
					N: 32,
				}
				return r
			}(),
		},
		{
			name: "valid-multi-wrapper-with-salt",
			args: args{
				wrapper:  pooledWrapper,
				lenLimit: 32,
				opt:      []wrapping.Option{crypto.WithSalt([]byte("salt"))},
			},
			want: func() *io.LimitedReader {
				raw := pooledWrapper.(*multi.PooledWrapper).WrapperForKeyId("__base__")
				b, err := raw.(*aead.Wrapper).KeyBytes(ctx)
				require.NoError(t, err)
				return &io.LimitedReader{
					R: hkdf.New(sha256.New, b, []byte("salt"), nil),
					N: 32,
				}
			}(),
		},
		{
			name: "unknown-wrapper",
			args: args{
				wrapper:  &unknownWrapper{},
				lenLimit: 20,
				opt:      []wrapping.Option{crypto.WithInfo([]byte("info")), crypto.WithSalt([]byte("salt"))},
			},
			wantErr:         true,
			wantErrCode:     wrapping.ErrInvalidParameter,
			wantErrContains: "wrapper does not implement required KeyBytes interface",
		},
		{
			name: "nil-wrapper",
			args: args{
				wrapper:  nil,
				lenLimit: 10,
				opt:      []wrapping.Option{crypto.WithInfo([]byte("info")), crypto.WithSalt([]byte("salt"))},
			},
			wantErr:         true,
			wantErrCode:     wrapping.ErrInvalidParameter,
			wantErrContains: "missing wrapper",
		},
		{
			name: "too-short",
			args: args{
				wrapper:  testWrapper,
				lenLimit: 10,
				opt:      []wrapping.Option{crypto.WithInfo([]byte("info")), crypto.WithSalt([]byte("salt"))},
			},
			wantErr:         true,
			wantErrCode:     wrapping.ErrInvalidParameter,
			wantErrContains: "lenLimit must be >= 20",
		},
		{
			name: "aead-wrapper-with-no-bytes",
			args: args{
				wrapper:  &aead.Wrapper{},
				lenLimit: 32,
				opt:      []wrapping.Option{crypto.WithSalt([]byte("salt"))},
			},
			wantErr:         true,
			wantErrCode:     wrapping.ErrInvalidParameter,
			wantErrContains: "missing bytes",
		},
		{
			name: "test-wrapper-with-no-bytes",
			args: args{
				wrapper:  &wrapping.TestWrapper{},
				lenLimit: 32,
				opt:      []wrapping.Option{crypto.WithSalt([]byte("salt"))},
			},
			wantErr:         true,
			wantErrCode:     wrapping.ErrInvalidParameter,
			wantErrContains: "missing bytes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := crypto.NewDerivedReader(context.Background(), tc.args.wrapper, tc.args.lenLimit, tc.args.opt...)
			if tc.wantErr {
				require.Error(err)
				assert.ErrorIsf(err, tc.wantErrCode, "unexpected error: %s", err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

type unknownWrapper struct {
	wrapping.Wrapper
}
