package aead

import (
	"crypto/sha256"
	"io"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/multi"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestNewDerivedReader(t *testing.T) {
	testWrapper := wrapping.NewTestWrapper([]byte("secret"))
	pooledWrapper := TestPooledWrapper(t)
	aeadWrapper := TestWrapper(t)

	type args struct {
		wrapper  wrapping.Wrapper
		lenLimit int64
		salt     []byte
		info     []byte
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
				info:     nil,
				salt:     []byte("salt"),
			},
			want: &io.LimitedReader{
				R: hkdf.New(sha256.New, aeadWrapper.(*Wrapper).GetKeyBytes(), []byte("salt"), nil),
				N: 32,
			},
		},
		{
			name: "valid-aead-with-salt-info",
			args: args{
				wrapper:  aeadWrapper,
				lenLimit: 32,
				info:     []byte("info"),
				salt:     []byte("salt"),
			},
			want: &io.LimitedReader{
				R: hkdf.New(sha256.New, aeadWrapper.(*Wrapper).GetKeyBytes(), []byte("salt"), []byte("info")),
				N: 32,
			},
		},
		{
			name: "valid-with-salt",
			args: args{
				wrapper:  testWrapper,
				lenLimit: 32,
				info:     nil,
				salt:     []byte("salt"),
			},
			want: &io.LimitedReader{
				R: hkdf.New(sha256.New, testWrapper.GetKeyBytes(), []byte("salt"), nil),
				N: 32,
			},
		},
		{
			name: "valid-with-salt-info",
			args: args{
				wrapper:  testWrapper,
				lenLimit: 32,
				info:     []byte("info"),
				salt:     []byte("salt"),
			},
			want: &io.LimitedReader{
				R: hkdf.New(sha256.New, testWrapper.GetKeyBytes(), []byte("salt"), []byte("info")),
				N: 32,
			},
		},
		{
			name: "valid-multi-wrapper-with-salt",
			args: args{
				wrapper:  pooledWrapper,
				lenLimit: 32,
				info:     nil,
				salt:     []byte("salt"),
			},
			want: func() *io.LimitedReader {
				raw := pooledWrapper.(*multi.PooledWrapper).WrapperForKeyId("__base__")
				return &io.LimitedReader{
					R: hkdf.New(sha256.New, raw.(*Wrapper).GetKeyBytes(), []byte("salt"), nil),
					N: 32,
				}
			}(),
		},
		{
			name: "unknown-wrapper",
			args: args{
				wrapper:  &unknownWrapper{},
				lenLimit: 20,
				info:     []byte("info"),
				salt:     []byte("salt"),
			},
			wantErr:         true,
			wantErrCode:     ErrInvalidParameter,
			wantErrContains: "unknown wrapper type",
		},
		{
			name: "nil-wrapper",
			args: args{
				wrapper:  nil,
				lenLimit: 10,
				info:     []byte("info"),
				salt:     []byte("salt"),
			},
			wantErr:         true,
			wantErrCode:     ErrInvalidParameter,
			wantErrContains: "missing wrapper",
		},
		{
			name: "too-short",
			args: args{
				wrapper:  testWrapper,
				lenLimit: 10,
				info:     []byte("info"),
				salt:     []byte("salt"),
			},
			wantErr:         true,
			wantErrCode:     ErrInvalidParameter,
			wantErrContains: "lenLimit must be >= 20",
		},
		{
			name: "aead-wrapper-with-no-bytes",
			args: args{
				wrapper:  &Wrapper{},
				lenLimit: 32,
				info:     nil,
				salt:     []byte("salt"),
			},
			wantErr:         true,
			wantErrCode:     ErrInvalidParameter,
			wantErrContains: "missing bytes",
		},
		{
			name: "test-wrapper-with-no-bytes",
			args: args{
				wrapper:  &wrapping.TestWrapper{},
				lenLimit: 32,
				info:     nil,
				salt:     []byte("salt"),
			},
			wantErr:         true,
			wantErrCode:     ErrInvalidParameter,
			wantErrContains: "missing bytes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewDerivedReader(tc.args.wrapper, tc.args.lenLimit, tc.args.salt, tc.args.info)
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
