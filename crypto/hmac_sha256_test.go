package crypto_test

import (
	"context"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_HmacSha256(t *testing.T) {
	testCtx := context.Background()
	testWrapper := wrapping.NewTestWrapper([]byte("secret"))
	tests := []struct {
		name            string
		data            []byte
		wrapper         wrapping.Wrapper
		salt            []byte
		info            []byte
		opts            []wrapping.Option
		wantHmac        string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "bad-wrapper",
			data:            []byte("test"),
			wrapper:         &wrapping.TestWrapper{},
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing bytes",
		},
		{
			name:            "bad-wrapper-with-ed25519",
			data:            []byte("test"),
			wrapper:         &wrapping.TestWrapper{},
			opts:            []wrapping.Option{crypto.WithEd25519()},
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing bytes",
		},
		{
			name:            "missing data",
			wrapper:         testWrapper,
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing data",
		},
		{
			name:            "missing wrapper",
			data:            []byte("test"),
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "you must specify either a wrapper or prk",
		},
		{
			name:            "prk-and-ed25519",
			data:            []byte("test"),
			wrapper:         nil,
			opts:            []wrapping.Option{crypto.WithPrk([]byte("prk")), crypto.WithEd25519()},
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "you cannot specify both ed25519 and a prk",
		},
		{
			name:            "prk-and-wrapper",
			data:            []byte("test"),
			wrapper:         testWrapper,
			opts:            []wrapping.Option{crypto.WithPrk([]byte("prk")), crypto.WithEd25519()},
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "you cannot specify both a wrapper or prk",
		},
		{
			name:     "blake2b-with-prefix",
			data:     []byte("test"),
			wrapper:  testWrapper,
			opts:     []wrapping.Option{crypto.WithPrefix("prefix:")},
			wantHmac: crypto.TestWithBlake2b(t, []byte("test"), testWrapper, nil, nil, crypto.WithPrefix("prefix:")),
		},
		{
			name:     "blake2b-with-prefix-with-base64",
			data:     []byte("test"),
			wrapper:  testWrapper,
			opts:     []wrapping.Option{crypto.WithPrefix("prefix:"), crypto.WithBase64Encoding()},
			wantHmac: crypto.TestWithBlake2b(t, []byte("test"), testWrapper, nil, nil, crypto.WithPrefix("prefix:"), crypto.WithBase64Encoding()),
		},
		{
			name:     "blake2b-with-prefix-with-base58",
			data:     []byte("test"),
			wrapper:  testWrapper,
			opts:     []wrapping.Option{crypto.WithPrefix("prefix:"), crypto.WithBase58Encoding()},
			wantHmac: crypto.TestWithBlake2b(t, []byte("test"), testWrapper, nil, nil, crypto.WithPrefix("prefix:"), crypto.WithBase58Encoding()),
		},
		{
			name:     "with-prk",
			data:     []byte("test"),
			opts:     []wrapping.Option{crypto.WithPrk([]byte("prk-0123456789012345678901234567890"))},
			wantHmac: crypto.TestWithBlake2b(t, []byte("test"), testWrapper, nil, nil, crypto.WithPrk([]byte("prk-0123456789012345678901234567890"))),
		},
		{
			name:     "withEd25519",
			data:     []byte("test"),
			wrapper:  testWrapper,
			opts:     []wrapping.Option{crypto.WithEd25519()},
			wantHmac: crypto.TestWithEd25519(t, []byte("test"), testWrapper, nil, nil),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			hm, err := crypto.HmacSha256(testCtx, tc.data, tc.wrapper, tc.salt, tc.info, tc.opts...)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.wantHmac, hm)
		})
	}

	t.Run("HmacSha256WithPrk", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		hm, err := crypto.HmacSha256WithPrk(testCtx, []byte("test"), []byte("prk-0123456789012345678901234567890"))
		require.NoError(err)
		want := crypto.TestWithBlake2b(t, []byte("test"), testWrapper, nil, nil, crypto.WithPrk([]byte("prk-0123456789012345678901234567890")))
		assert.Equal(want, hm)
	})
}
