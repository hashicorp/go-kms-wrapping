package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewRootKeyVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		rootKeyId       string
		key             []byte
		want            *rootKeyVersion
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-root-key-id",
			key:             []byte("key"),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key id",
		},
		{
			name:            "missing-key",
			rootKeyId:       "root-key-id",
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key",
		},
		{
			name:      "valid",
			rootKeyId: "root-key-id",
			key:       []byte("key"),
			want: &rootKeyVersion{
				RootKeyId: "root-key-id",
				Key:       []byte("key"),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newRootKeyVersion(tc.rootKeyId, tc.key)
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
			assert.Equal(tc.want, got)
		})
	}
}

func TestRootKeyVersion_vetForWrite(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		key             *rootKeyVersion
		opType          dbw.OpType
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "create-missing-private-id",
			key: &rootKeyVersion{
				RootKeyId: "root-key-id",
				CtKey:     []byte("key"),
			},
			opType:          dbw.CreateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "create-missing-ct-key",
			key: &rootKeyVersion{
				PrivateId: "private-id",
				RootKeyId: "root-key-id",
			},
			opType:          dbw.CreateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key",
		},
		{
			name: "create-missing-root-key-id",
			key: &rootKeyVersion{
				PrivateId: "private-id",
				CtKey:     []byte("key"),
			},
			opType:          dbw.CreateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key id",
		},
		{
			name: "update-immutable",
			key: &rootKeyVersion{
				PrivateId: "private-id",
			},
			opType:          dbw.UpdateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "key is immutable",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tc.key.vetForWrite(testCtx, tc.opType)
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
		})
	}
}

func TestRootKeyVersion_Encrypt(t *testing.T) {
	t.Parallel()
	const (
		testKey = "test-key"
	)
	testCtx := context.Background()
	testWrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	tests := []struct {
		name            string
		key             *rootKeyVersion
		wrapper         wrapping.Wrapper
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "bad-cipher",
			key: &rootKeyVersion{
				Key: []byte(testKey),
			},
			wrapper:         aead.NewWrapper(),
			wantErr:         true,
			wantErrContains: "error wrapping value",
		},
		{
			name: "missing-cipher",
			key: &rootKeyVersion{
				Key: []byte(testKey),
			},
			wantErr:         true,
			wantErrContains: "missing cipher",
		},
		{
			name: "success",
			key: &rootKeyVersion{
				Key: []byte(testKey),
			},
			wrapper: testWrapper,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.Empty(tc.key.CtKey)
			require.NotEmpty(tc.key.Key)
			err := tc.key.Encrypt(testCtx, tc.wrapper)
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
			assert.NotEmpty(tc.key.CtKey)
			tc.key.Key = nil
			err = tc.key.Decrypt(testCtx, tc.wrapper)
			require.NoError(err)
			assert.Equal(testKey, string(tc.key.Key))
		})
	}
}

func TestRootKeyVersion_Decrypt(t *testing.T) {
	t.Parallel()
	const (
		testKey = "test-key"
	)
	testCtx := context.Background()
	testWrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	testDataKey := &rootKeyVersion{
		Key: []byte(testKey),
	}
	err := testDataKey.Encrypt(testCtx, testWrapper)
	require.NoError(t, err)
	tests := []struct {
		name            string
		key             *rootKeyVersion
		wrapper         wrapping.Wrapper
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "bad-cipher",
			key:             testDataKey,
			wrapper:         aead.NewWrapper(),
			wantErr:         true,
			wantErrContains: "error unwrapping value",
		},
		{
			name:            "missing-cipher",
			key:             testDataKey,
			wantErr:         true,
			wantErrContains: "missing cipher",
		},
		{
			name:    "success",
			key:     testDataKey,
			wrapper: testWrapper,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NotEmpty(tc.key.CtKey)
			require.NotEmpty(tc.key.Key)
			err := tc.key.Decrypt(testCtx, tc.wrapper)
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
			assert.Equal(testKey, string(tc.key.Key))
		})
	}
}
