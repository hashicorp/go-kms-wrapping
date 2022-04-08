package kms_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKms_New(t *testing.T) {
	t.Parallel()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	testRepo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)

	tests := []struct {
		name            string
		repo            *kms.Repository
		purposes        []kms.KeyPurpose
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-repo",
			purposes:        []kms.KeyPurpose{kms.KeyPurposeRootKey, "database"},
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing underlying repo",
		},
		{
			name: "nil-purpose",
			repo: testRepo,
		},
		{
			name:     "with-purposes",
			repo:     testRepo,
			purposes: []kms.KeyPurpose{"database", "audit"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			k, err := kms.New(tc.repo, tc.purposes)
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
			assert.NotNil(k)
			tc.purposes = append(tc.purposes, kms.KeyPurposeRootKey)
			kms.RemoveDuplicatePurposes(tc.purposes)
			assert.Equal(tc.purposes, k.Purposes())
		})
	}
}

func TestKms_AddExternalWrapper(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	testRepo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))

	tests := []struct {
		name            string
		repo            *kms.Repository
		kmsPurposes     []kms.KeyPurpose
		wrapper         wrapping.Wrapper
		wrapperPurpose  kms.KeyPurpose
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-purpose",
			repo:            testRepo,
			kmsPurposes:     []kms.KeyPurpose{"audit"},
			wrapper:         wrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing purpose",
		},
		{
			name:            "nil-wrapper",
			repo:            testRepo,
			kmsPurposes:     []kms.KeyPurpose{"recovery"},
			wrapperPurpose:  "recovery",
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing wrapper",
		},
		{
			name:            "unsupported-purpose",
			repo:            testRepo,
			kmsPurposes:     []kms.KeyPurpose{"audit"},
			wrapper:         wrapper,
			wrapperPurpose:  "recovery",
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "not a supported key purpose",
		},
		{
			name:            "wrapper-key-id-error",
			repo:            testRepo,
			kmsPurposes:     []kms.KeyPurpose{"recovery"},
			wrapper:         &mockTestWrapper{err: errors.New("KeyId error")},
			wrapperPurpose:  "recovery",
			wantErr:         true,
			wantErrContains: "KeyId error",
		},
		{
			name:            "wrapper-missing-key-id",
			repo:            testRepo,
			kmsPurposes:     []kms.KeyPurpose{"recovery"},
			wrapper:         aead.NewWrapper(),
			wrapperPurpose:  "recovery",
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "wrapper has no key ID",
		},
		{
			name:           "success-non-default-purpose",
			repo:           testRepo,
			kmsPurposes:    []kms.KeyPurpose{"recovery"},
			wrapper:        wrapper,
			wrapperPurpose: "recovery",
		},
		{
			name: "success",
			repo: testRepo,
			// use the default kmsPurposes
			wrapper:        wrapper,
			wrapperPurpose: kms.KeyPurposeRootKey,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			k, err := kms.New(tc.repo, tc.kmsPurposes)
			require.NoError(err)

			err = k.AddExternalWrapper(testCtx, tc.wrapperPurpose, tc.wrapper)
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
			w, err := k.GetExternalWrapper(testCtx, tc.wrapperPurpose)
			require.NoError(err)
			assert.Equal(tc.wrapper, w)
		})
	}
}

func TestKms_GetExternalWrapper(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	testRepo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))

	tests := []struct {
		name            string
		kms             *kms.Kms
		wrapperPurpose  kms.KeyPurpose
		want            wrapping.Wrapper
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "missing-purpose",
			kms: func() *kms.Kms {
				k, err := kms.New(testRepo, []kms.KeyPurpose{"recovery"})
				require.NoError(t, err)
				k.AddExternalWrapper(testCtx, "recovery", wrapper)
				return k
			}(),
			want:            wrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing purpose",
		},
		{
			name: "invalid-purpose",
			kms: func() *kms.Kms {
				k, err := kms.New(testRepo, []kms.KeyPurpose{"recovery"})
				require.NoError(t, err)
				k.AddExternalWrapper(testCtx, "recovery", wrapper)
				return k
			}(),
			wrapperPurpose:  "invalid",
			want:            wrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "not a supported key purpose",
		},
		{
			name: "missing-external-wrapper",
			kms: func() *kms.Kms {
				k, err := kms.New(testRepo, []kms.KeyPurpose{"recovery"})
				require.NoError(t, err)
				return k
			}(),
			wrapperPurpose:  "recovery",
			want:            wrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrKeyNotFound,
			wantErrContains: " missing external wrapper for",
		},
		{
			name: "success",
			kms: func() *kms.Kms {
				k, err := kms.New(testRepo, []kms.KeyPurpose{"recovery"})
				require.NoError(t, err)
				k.AddExternalWrapper(testCtx, "recovery", wrapper)
				return k
			}(),
			wrapperPurpose: "recovery",
			want:           wrapper,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := tc.kms.GetExternalWrapper(testCtx, tc.wrapperPurpose)
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

func TestKms_GetExternalRootWrapper(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	testRepo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))

	tests := []struct {
		name            string
		kms             *kms.Kms
		want            wrapping.Wrapper
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "missing-root-wrapper",
			kms: func() *kms.Kms {
				k, err := kms.New(testRepo, nil)
				require.NoError(t, err)
				return k
			}(),
			wantErr:         true,
			wantErrIs:       kms.ErrKeyNotFound,
			wantErrContains: "missing external root wrapper",
		},
		{
			name: "success",
			kms: func() *kms.Kms {
				k, err := kms.New(testRepo, nil)
				require.NoError(t, err)
				k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				return k
			}(),
			want: wrapper,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.kms.GetExternalRootWrapper()
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

func TestKms_GetWrapper(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	testRepo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))

	tests := []struct {
		name            string
		kms             *kms.Kms
		repo            *kms.Repository
		scopeId         string
		purpose         kms.KeyPurpose
		opt             []kms.Option
		setup           func(*kms.Repository)
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-scope-id",
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing scope id",
		},
		{
			name:            "missing-purpose",
			scopeId:         "global",
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing purpose",
		},
		{
			name:    "invalid-purpose",
			scopeId: "global",
			purpose: "invalid",
			kms: func() *kms.Kms {
				k, err := kms.New(testRepo, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				return k
			}(),
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "not a supported key purpose",
		},
		{
			name: "load-root-error",
			kms: func() *kms.Kms {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("load-root-error"))
				require.NoError(t, err)
				r, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				k, err := kms.New(r, []kms.KeyPurpose{"database"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			purpose:         "database",
			wantErr:         true,
			wantErrContains: "error loading root key for scope",
		},
		{
			name: "load-dek-error",
			kms: func() *kms.Kms {
				k, err := kms.New(testRepo, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				return k
			}(),
			setup: func(r *kms.Repository) {
				kms.TestDeleteWhere(t, db, &kms.RootKey{}, "1=1")
				_, err := r.CreateKeysTx(testCtx, wrapper, rand.Reader, "global", "database", "auth")
				require.NoError(t, err)
				kms.TestDeleteWhere(t, db, &kms.DataKeyVersion{}, "1=1")
				require.NoError(t, err)
			},
			repo:            testRepo,
			scopeId:         "global",
			purpose:         "database",
			wantErr:         true,
			wantErrContains: `error loading "database" for scope`,
		},
		{
			name: "success",
			kms: func() *kms.Kms {
				k, err := kms.New(testRepo, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				return k
			}(),
			setup: func(r *kms.Repository) {
				kms.TestDeleteWhere(t, db, &kms.RootKey{}, "1=1")
				_, err := r.CreateKeysTx(testCtx, wrapper, rand.Reader, "global", "database", "auth")
				require.NoError(t, err)
			},
			repo:    testRepo,
			scopeId: "global",
			purpose: "database",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tc.setup != nil {
				tc.setup(tc.repo)
			}
			got, err := tc.kms.GetWrapper(testCtx, tc.scopeId, tc.purpose, tc.opt...)
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
			assert.NotNil(got)
		})
	}
}
