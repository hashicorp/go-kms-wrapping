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

func Test_NewDataKeyVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		dataKeyId        string
		rootKeyVersionId string
		key              []byte
		want             *dataKeyVersion
		wantErr          bool
		wantErrIs        error
		wantErrContains  string
	}{
		{
			name:             "missing-data-key-id",
			rootKeyVersionId: "root-key-version-id",
			key:              []byte("key"),
			wantErr:          true,
			wantErrIs:        ErrInvalidParameter,
			wantErrContains:  "missing data key id",
		},
		{
			name:            "missing-root-key-version-id",
			dataKeyId:       "data-key-id",
			key:             []byte("key"),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key version id",
		},
		{
			name:             "missing-key",
			dataKeyId:        "data-key-id",
			rootKeyVersionId: "root-key-version-id",
			wantErr:          true,
			wantErrIs:        ErrInvalidParameter,
			wantErrContains:  "missing key",
		},
		{
			name:             "valid",
			dataKeyId:        "data-key-id",
			rootKeyVersionId: "root-key-version-id",
			key:              []byte("key"),
			want: &dataKeyVersion{
				DataKeyId:        "data-key-id",
				RootKeyVersionId: "root-key-version-id",
				Key:              []byte("key"),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newDataKeyVersion(tc.dataKeyId, tc.key, tc.rootKeyVersionId)
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

func TestDataKeyVersion_vetForWrite(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		key             *dataKeyVersion
		opType          dbw.OpType
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "create-missing-private-id",
			key: &dataKeyVersion{
				DataKeyId:        "data-key-id",
				RootKeyVersionId: "root-key-version-id",
				CtKey:            []byte("key"),
			},
			opType:          dbw.CreateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "create-missing-ct-key",
			key: &dataKeyVersion{
				PrivateId:        "private-id",
				DataKeyId:        "data-key-id",
				RootKeyVersionId: "root-key-version-id",
			},
			opType:          dbw.CreateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key",
		},
		{
			name: "create-missing-data-key-id",
			key: &dataKeyVersion{
				PrivateId:        "private-id",
				CtKey:            []byte("key"),
				RootKeyVersionId: "root-key-version-id",
			},
			opType:          dbw.CreateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing data key id",
		},
		{
			name: "create-missing-root-key-version-id",
			key: &dataKeyVersion{
				PrivateId: "private-id",
				CtKey:     []byte("key"),
				DataKeyId: "data-key-id",
			},
			opType:          dbw.CreateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key version id",
		},
		{
			name: "update-immutable",
			key: &dataKeyVersion{
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

func TestDataKeyVersion_Encrypt(t *testing.T) {
	t.Parallel()
	const (
		testKey = "test-key"
	)
	testCtx := context.Background()
	testWrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	tests := []struct {
		name            string
		key             *dataKeyVersion
		wrapper         wrapping.Wrapper
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "bad-cipher",
			key: &dataKeyVersion{
				Key: []byte(testKey),
			},
			wrapper:         aead.NewWrapper(),
			wantErr:         true,
			wantErrContains: "error wrapping value",
		},
		{
			name: "missing-cipher",
			key: &dataKeyVersion{
				Key: []byte(testKey),
			},
			wantErr:         true,
			wantErrContains: "missing cipher",
		},
		{
			name: "success",
			key: &dataKeyVersion{
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
			assert.NotEqual(tc.key.CtKey, tc.key.Key)
			assert.NotEmpty(tc.key.CtKey)
			tc.key.Key = nil
			err = tc.key.Decrypt(testCtx, tc.wrapper)
			require.NoError(err)
			assert.Equal(testKey, string(tc.key.Key))
		})
	}
}

func TestDataKeyVersion_Decrypt(t *testing.T) {
	t.Parallel()
	const (
		testKey = "test-key"
	)
	testCtx := context.Background()
	testWrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	testDataKey := &dataKeyVersion{
		Key: []byte(testKey),
	}
	err := testDataKey.Encrypt(testCtx, testWrapper)
	require.NoError(t, err)
	tests := []struct {
		name            string
		key             *dataKeyVersion
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
