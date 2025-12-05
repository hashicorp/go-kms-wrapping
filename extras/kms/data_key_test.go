// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewDataKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		rootKeyId       string
		purpose         KeyPurpose
		want            *dataKey
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-root-key-id",
			purpose:         "database",
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key id",
		},
		{
			name:            "missing-purpose",
			rootKeyId:       "root-key-id",
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing purpose",
		},
		{
			name:            "invalid-purpose",
			rootKeyId:       "root-key-id",
			purpose:         KeyPurposeRootKey,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: fmt.Sprintf("cannot be a purpose of %q", KeyPurposeRootKey),
		},
		{
			name:      "valid",
			rootKeyId: "root-key-id",
			purpose:   "database",
			want: &dataKey{
				RootKeyId: "root-key-id",
				Purpose:   "database",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newDataKey(tc.rootKeyId, tc.purpose)
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

func TestDataKey_vetForWrite(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		key             *dataKey
		opType          dbw.OpType
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "create-missing-private-id",
			key: &dataKey{
				RootKeyId: "root-key-id",
				Purpose:   "database",
			},
			opType:          dbw.CreateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "create-missing-root-key",
			key: &dataKey{
				PrivateId: "private-key-id",
				Purpose:   "database",
			},
			opType:          dbw.CreateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key",
		},
		{
			name: "create-invalid-purpose",
			key: &dataKey{
				PrivateId: "private-key-id",
				RootKeyId: "root-key-id",
				Purpose:   KeyPurposeRootKey,
			},
			opType:          dbw.CreateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: fmt.Sprintf("cannot be a purpose of %q", KeyPurposeRootKey),
		},
		{
			name: "create-missing-purpose",
			key: &dataKey{
				PrivateId: "private-key-id",
				RootKeyId: "root-key-id",
			},
			opType:          dbw.CreateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing purpose",
		},
		{
			name: "invalid-update",
			key: &dataKey{
				PrivateId: "private-key-id",
				RootKeyId: "root-key-id",
				Purpose:   "database",
			},
			opType:          dbw.UpdateOp,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "data key is immutable",
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

func TestDataKey_GetRootKeyId(t *testing.T) {
	t.Parallel()
	k := &dataKey{
		RootKeyId: "root-key-id",
	}
	assert.Equal(t, "root-key-id", k.GetRootKeyId())
}
