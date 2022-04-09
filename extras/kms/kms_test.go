package kms_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
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

func testDeleteWhere(t *testing.T, conn *dbw.DB, i interface{}, whereClause string, args ...interface{}) {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()
	tabler, ok := i.(interface {
		TableName() string
	})
	require.True(ok)
	_, err := dbw.New(conn).Exec(ctx, fmt.Sprintf(`delete from "%s" where %s`, tabler.TableName(), whereClause), []interface{}{args})
	require.NoError(err)
}

const defaultWrapperSecret = "secret1234567890"

type rootKey struct{}

func (k *rootKey) TableName() string { return "kms_root_key" }

type dataKeyVersion struct{}

func (k *dataKeyVersion) TableName() string { return "kms_data_key_version" }

func removeDuplicatePurposes(purposes []kms.KeyPurpose) []kms.KeyPurpose {
	purposesMap := make(map[kms.KeyPurpose]struct{}, len(purposes))
	for _, purpose := range purposes {
		purpose = kms.KeyPurpose(strings.TrimSpace(string(purpose)))
		if purpose == "" {
			continue
		}
		purposesMap[purpose] = struct{}{}
	}
	purposes = make([]kms.KeyPurpose, 0, len(purposesMap))
	for purpose := range purposesMap {
		purposes = append(purposes, purpose)
	}
	return purposes
}

type mockTestWrapper struct {
	wrapping.Wrapper
	err   error
	keyId string
}

func (m *mockTestWrapper) KeyId(context.Context) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.keyId, nil
}

func TestKms_New(t *testing.T) {
	t.Parallel()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	tests := []struct {
		name            string
		reader          dbw.Reader
		writer          dbw.Writer
		purposes        []kms.KeyPurpose
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-reader",
			purposes:        []kms.KeyPurpose{kms.KeyPurposeRootKey, "database"},
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "nil reader",
		},
		{
			name:            "missing-writer",
			purposes:        []kms.KeyPurpose{kms.KeyPurposeRootKey, "database"},
			reader:          rw,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "nil writer",
		},
		{
			name:   "nil-purpose",
			reader: rw,
			writer: rw,
		},
		{
			name:     "with-purposes",
			reader:   rw,
			writer:   rw,
			purposes: []kms.KeyPurpose{"database", "audit"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			k, err := kms.New(tc.reader, tc.writer, tc.purposes)
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
			removeDuplicatePurposes(tc.purposes)
			assert.Equal(tc.purposes, k.Purposes())
		})
	}
}

func TestKms_AddExternalWrapper(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))

	tests := []struct {
		name            string
		reader          dbw.Reader
		writer          dbw.Writer
		kmsPurposes     []kms.KeyPurpose
		wrapper         wrapping.Wrapper
		wrapperPurpose  kms.KeyPurpose
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-purpose",
			reader:          rw,
			writer:          rw,
			kmsPurposes:     []kms.KeyPurpose{"audit"},
			wrapper:         wrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing purpose",
		},
		{
			name:            "nil-wrapper",
			reader:          rw,
			writer:          rw,
			kmsPurposes:     []kms.KeyPurpose{"recovery"},
			wrapperPurpose:  "recovery",
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing wrapper",
		},
		{
			name:            "unsupported-purpose",
			reader:          rw,
			writer:          rw,
			kmsPurposes:     []kms.KeyPurpose{"audit"},
			wrapper:         wrapper,
			wrapperPurpose:  "recovery",
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "not a supported key purpose",
		},
		{
			name:            "wrapper-key-id-error",
			reader:          rw,
			writer:          rw,
			kmsPurposes:     []kms.KeyPurpose{"recovery"},
			wrapper:         &mockTestWrapper{err: errors.New("KeyId error")},
			wrapperPurpose:  "recovery",
			wantErr:         true,
			wantErrContains: "KeyId error",
		},
		{
			name:            "wrapper-missing-key-id",
			reader:          rw,
			writer:          rw,
			kmsPurposes:     []kms.KeyPurpose{"recovery"},
			wrapper:         aead.NewWrapper(),
			wrapperPurpose:  "recovery",
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "wrapper has no key ID",
		},
		{
			name:           "success-non-default-purpose",
			reader:         rw,
			writer:         rw,
			kmsPurposes:    []kms.KeyPurpose{"recovery"},
			wrapper:        wrapper,
			wrapperPurpose: "recovery",
		},
		{
			name:   "success",
			reader: rw,
			writer: rw,
			// use the default kmsPurposes
			wrapper:        wrapper,
			wrapperPurpose: kms.KeyPurposeRootKey,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			k, err := kms.New(tc.reader, tc.writer, tc.kmsPurposes)
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
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))

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
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"recovery"})
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
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"recovery"})
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
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"recovery"})
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
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"recovery"})
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
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))

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
				k, err := kms.New(rw, rw, nil)
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
				k, err := kms.New(rw, rw, nil)
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
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))

	tests := []struct {
		name            string
		kms             *kms.Kms
		reader          dbw.Reader
		writer          dbw.Writer
		scopeId         string
		purpose         kms.KeyPurpose
		opt             []kms.Option
		setup           func(*kms.Kms)
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
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"database", "auth"})
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
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"database"})
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
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				return k
			}(),
			setup: func(k *kms.Kms) {
				testDeleteWhere(t, db, &rootKey{}, "1=1")

				err := k.CreateKeys(testCtx, "global", []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				testDeleteWhere(t, db, &dataKeyVersion{}, "1=1")
				require.NoError(t, err)
			},
			scopeId:         "global",
			purpose:         "database",
			wantErr:         true,
			wantErrContains: `error loading "database" for scope`,
		},
		{
			name: "success",
			kms: func() *kms.Kms {
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				return k
			}(),
			setup: func(k *kms.Kms) {
				testDeleteWhere(t, db, &rootKey{}, "1=1")
				err := k.CreateKeys(testCtx, "global", []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
			},
			scopeId: "global",
			purpose: "database",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tc.setup != nil {
				tc.setup(tc.kms)
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

func TestKms_CreateKeys(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	tests := []struct {
		name            string
		kms             *kms.Kms
		scopeId         string
		purposes        []kms.KeyPurpose
		opt             []kms.Option
		setup           func(*kms.Kms)
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "missing-scope-id",
			kms: func() *kms.Kms {
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing scope id",
		},
		{
			name: "missing-external-root-wrapper",
			kms: func() *kms.Kms {
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			wantErr:         true,
			wantErrIs:       kms.ErrKeyNotFound,
			wantErrContains: "missing external root wrapper",
		},
		{
			name: "begin-error",
			kms: func() *kms.Kms {
				db, mock := dbw.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectBegin().WillReturnError(errors.New("begin-error"))
				rw := dbw.New(db)
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId: "global",
			setup: func(k *kms.Kms) {
				testDeleteWhere(t, db, &rootKey{}, "1=1")
			},
			wantErr:         true,
			wantErrContains: "begin-error",
		},
		{
			name: "create-error",
			kms: func() *kms.Kms {
				db, mock := dbw.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectBegin()
				mock.ExpectQuery(`INSERT INTO "kms_root_key"`).WillReturnError(errors.New("create-error"))
				mock.ExpectRollback()
				rw := dbw.New(db)
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId: "global",
			setup: func(k *kms.Kms) {
				testDeleteWhere(t, db, &rootKey{}, "1=1")
			},
			wantErr:         true,
			wantErrContains: "create-error",
		},
		{
			name: "rollback-error",
			kms: func() *kms.Kms {
				db, mock := dbw.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectBegin()
				mock.ExpectQuery(`INSERT INTO "kms_root_key"`).WillReturnError(errors.New("create-error"))
				mock.ExpectRollback().WillReturnError(errors.New("rollback-error"))
				rw := dbw.New(db)
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId: "global",
			setup: func(k *kms.Kms) {
				testDeleteWhere(t, db, &rootKey{}, "1=1")
			},
			wantErr:         true,
			wantErrContains: "rollback-error",
		},
		{
			name: "success-no-opts",
			kms: func() *kms.Kms {
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId: "global",
			setup: func(k *kms.Kms) {
				testDeleteWhere(t, db, &rootKey{}, "1=1")
			},
		},
		{
			name: "success-with-rand",
			kms: func() *kms.Kms {
				k, err := kms.New(rw, rw, []kms.KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId: "global",
			setup: func(k *kms.Kms) {
				testDeleteWhere(t, db, &rootKey{}, "1=1")
			},
			opt: []kms.Option{kms.WithRandomReader(rand.Reader)},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tc.setup != nil {
				tc.setup(tc.kms)
			}
			err := tc.kms.CreateKeys(testCtx, tc.scopeId, tc.purposes, tc.opt...)
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
			for _, kp := range tc.purposes {
				w, err := tc.kms.GetWrapper(testCtx, tc.scopeId, kp)
				require.NoError(err)
				assert.NotNil(w)
			}
		})
	}
	t.Run("WithTx", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		db, _ := kms.TestDb(t)
		rw := dbw.New(db)
		purposes := []kms.KeyPurpose{"database"}
		k, err := kms.New(rw, rw, purposes)
		require.NoError(err)
		err = k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
		require.NoError(err)

		tx, err := rw.Begin(testCtx)
		require.NoError(err)

		err = k.CreateKeys(testCtx, "global", []kms.KeyPurpose{"database"}, kms.WithTx(tx))
		require.NoError(err)

		assert.NoError(tx.Commit(testCtx))

		for _, kp := range purposes {
			w, err := k.GetWrapper(testCtx, "global", kp)
			require.NoError(err)
			assert.NotNil(w)
		}
	})
	t.Run("WithTx-missing", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		db, _ := kms.TestDb(t)
		rw := dbw.New(db)
		purposes := []kms.KeyPurpose{"database"}
		k, err := kms.New(rw, rw, purposes)
		require.NoError(err)
		err = k.AddExternalWrapper(testCtx, kms.KeyPurposeRootKey, wrapper)
		require.NoError(err)

		err = k.CreateKeys(testCtx, "global", []kms.KeyPurpose{"database"}, kms.WithTx(rw))
		require.Error(err)
		assert.ErrorIs(err, kms.ErrInvalidParameter)

		for _, kp := range purposes {
			w, err := k.GetWrapper(testCtx, "global", kp)
			require.Error(err)
			assert.Nil(w)
		}
	})
}

func TestRepository_ValidateVersion(t *testing.T) {
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	tests := []struct {
		name            string
		kms             *kms.Kms
		wantVersion     string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "valid",
			kms: func() *kms.Kms {
				k, err := kms.New(rw, rw, nil)
				require.NoError(t, err)
				return k
			}(),
			wantVersion: migrations.Version,
		},
		{
			name: "invalid-version",
			kms: func() *kms.Kms {
				mDb, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(mDb)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(100))
				k, err := kms.New(rw, rw, nil)
				require.NoError(t, err)
				return k
			}(),
			wantErr:         true,
			wantErrContains: "invalid version",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			version, err := tc.kms.ValidateSchema(testCtx)
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
			assert.Equal(tc.wantVersion, version)
		})
	}
}
