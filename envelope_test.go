package wrapping

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_EnvelopeEncrypt(t *testing.T) {
	tests := []struct {
		name            string
		pt              []byte
		want            []byte
		encryptOpt      []Option
		decryptOpt      []Option
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "options-error",
			encryptOpt:      []Option{testOptionWithError(t)},
			wantErr:         true,
			wantErrContains: "option error",
		},
		{
			name:       "success-with-aad",
			pt:         []byte("test"),
			want:       []byte("test"),
			encryptOpt: []Option{WithAad([]byte("aad"))},
			decryptOpt: []Option{WithAad([]byte("aad"))},
		},
		{
			name:       "success-with-nil-aad",
			pt:         []byte("test"),
			want:       []byte("test"),
			encryptOpt: []Option{WithAad(nil)},
		},
		{
			name:       "success-with-empty-aad",
			pt:         []byte("test"),
			want:       []byte("test"),
			encryptOpt: []Option{WithAad([]byte(""))},
		},
		{
			name:       "success-with-empty-pt",
			pt:         []byte(""),
			want:       []byte(nil), // **** NOTE: this is a bit different: you get back nil instead of ""
			encryptOpt: []Option{WithAad([]byte("aad"))},
			decryptOpt: []Option{WithAad([]byte("aad"))},
		},
		{
			name: "success-with-nil-pt",
			pt:   []byte(nil),
			want: []byte(nil),
		},
		{
			name: "success",
			pt:   []byte("test"),
			want: []byte("test"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			env, err := EnvelopeEncrypt(tc.pt, tc.encryptOpt...)
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
			assert.NotNil(env)
			assert.NotEmpty(env.Ciphertext)
			assert.NotEmpty(env.Iv)
			assert.NotEmpty(env.Key)

			output, err := EnvelopeDecrypt(env, tc.decryptOpt...)
			require.NoError(err)

			require.Equal(tc.want, output)
		})
	}
}

func Test_EnvelopeDecrypt(t *testing.T) {
	tests := []struct {
		name            string
		pt              []byte
		want            []byte
		setup           func([]byte, ...Option) *EnvelopeInfo
		setupOpt        []Option
		decryptOpt      []Option
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "missing-data",
			setup: func(pt []byte, opt ...Option) *EnvelopeInfo {
				return nil
			},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing envelope info",
		},
		{
			name: "options-error",
			pt:   []byte("test"),
			setup: func(pt []byte, opt ...Option) *EnvelopeInfo {
				env, err := EnvelopeEncrypt(pt, opt...)
				require.NoError(t, err)
				return env
			},
			decryptOpt:      []Option{testOptionWithError(t)},
			wantErr:         true,
			wantErrContains: "option error",
		},
		{
			name: "fail-not-matching-aad",
			pt:   []byte("test"),
			setup: func(pt []byte, opt ...Option) *EnvelopeInfo {
				env, err := EnvelopeEncrypt(pt, opt...)
				require.NoError(t, err)
				return env
			},
			decryptOpt:      []Option{WithAad([]byte("not-matching"))},
			wantErr:         true,
			wantErrContains: "message authentication failed",
		},
		{
			name:     "success-with-nil-aad",
			pt:       []byte("test"),
			setupOpt: []Option{WithAad(nil)},
			setup: func(pt []byte, opt ...Option) *EnvelopeInfo {
				env, err := EnvelopeEncrypt(pt, opt...)
				require.NoError(t, err)
				return env
			},
			decryptOpt: []Option{WithAad(nil)},
			want:       []byte("test"),
		},
		{
			name:     "success-with-empty-aad",
			pt:       []byte("test"),
			setupOpt: []Option{WithAad([]byte(""))},
			setup: func(pt []byte, opt ...Option) *EnvelopeInfo {
				env, err := EnvelopeEncrypt(pt, opt...)
				require.NoError(t, err)
				return env
			},
			decryptOpt: []Option{WithAad([]byte(""))},
			want:       []byte("test"),
		},
		{
			name:     "success-with-matching-aad",
			pt:       []byte("test"),
			setupOpt: []Option{WithAad([]byte("matching"))},
			setup: func(pt []byte, opt ...Option) *EnvelopeInfo {
				env, err := EnvelopeEncrypt(pt, opt...)
				require.NoError(t, err)
				return env
			},
			decryptOpt: []Option{WithAad([]byte("matching"))},
			want:       []byte("test"),
		},
		{
			name: "success-no-aad",
			pt:   []byte("test"),
			setup: func(pt []byte, opt ...Option) *EnvelopeInfo {
				env, err := EnvelopeEncrypt(pt, opt...)
				require.NoError(t, err)
				return env
			},
			want: []byte("test"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			env := tc.setup(tc.pt, tc.setupOpt...)

			output, err := EnvelopeDecrypt(env, tc.decryptOpt...)
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
			assert.NotNil(env)
			require.Equal(tc.want, output)
		})
	}
}

func Test_aeadEncrypter(t *testing.T) {
	tests := []struct {
		name            string
		key             []byte
		wantErr         bool
		wantErrContains string
	}{
		{
			name:            "missing-key",
			wantErr:         true,
			wantErrContains: "invalid key size 0",
		},
		{
			name:            "invalid-key-size",
			key:             []byte("01234567"),
			wantErr:         true,
			wantErrContains: "invalid key size 8",
		},
		{
			name: "success",
			key:  []byte("0123456789123456"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := aeadEncrypter(tc.key)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(got)
		})
	}
}
