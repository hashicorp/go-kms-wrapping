package kms

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/multi"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKms_loadDek(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	rk := testRootKey(t, db, "global")
	_, rkw := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
	dk := testDataKey(t, db, rk.PrivateId, "database")
	const (
		testKey1 = "1234567890123456"
		testKey2 = "2234567890123456"
	)
	_ = testDataKeyVersion(t, db, rkw, dk.PrivateId, []byte(testKey1))
	dkv := testDataKeyVersion(t, db, rkw, dk.PrivateId, []byte(testKey2))

	tests := []struct {
		name            string
		kms             *Kms
		scopeId         string
		purpose         KeyPurpose
		rootWrapper     wrapping.Wrapper
		rootKeyId       string
		opt             []Option
		want            []byte
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "missing-scope-id",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database"})
				require.NoError(t, err)
				return k
			}(),
			purpose:         "database",
			rootWrapper:     rkw,
			rootKeyId:       rk.PrivateId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing scope id",
		},
		{
			name: "missing-wrapper",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database"})
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			purpose:         "database",
			rootKeyId:       rk.PrivateId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "nil root wrapper for scope",
		},
		{
			name: "missing-root-key-id",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database"})
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			purpose:         "database",
			rootWrapper:     rkw,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key ID for scope",
		},
		{
			name: "invalid-purpose",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database"})
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			purpose:         "invalid-purpose",
			rootWrapper:     rkw,
			rootKeyId:       rk.PrivateId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "not a supported key purpose",
		},
		{
			name: "list-keys-error",
			kms: func() *Kms {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("list-keys-error"))
				k, err := New(rw, rw, []KeyPurpose{"database"})
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			purpose:         "database",
			rootWrapper:     rkw,
			rootKeyId:       rk.PrivateId,
			wantErr:         true,
			wantErrContains: "list-keys-error",
		},
		{
			name: "list-keys-not-found",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			purpose:         "auth",
			rootWrapper:     rkw,
			rootKeyId:       rk.PrivateId,
			wantErr:         true,
			wantErrIs:       ErrKeyNotFound,
			wantErrContains: "key not found",
		},
		{
			name: "list-key-version-error",
			kms: func() *Kms {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "root_key_id", "create_time"}).AddRow(dk.PrivateId, rk.PrivateId, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("list-key-version-error"))
				k, err := New(rw, rw, []KeyPurpose{"database"})
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			purpose:         "database",
			rootWrapper:     rkw,
			rootKeyId:       rk.PrivateId,
			wantErr:         true,
			wantErrContains: "list-key-version-error",
		},
		{
			name: "list-key-version-no-rows",
			kms: func() *Kms {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "root_key_id", "create_time"}).AddRow(dk.PrivateId, rk.PrivateId, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "root_key_id", "create_time"}))
				k, err := New(rw, rw, []KeyPurpose{"database"})
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			purpose:         "database",
			rootWrapper:     rkw,
			rootKeyId:       rk.PrivateId,
			wantErr:         true,
			wantErrContains: "key not found",
		},
		{
			name: "success",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database"})
				require.NoError(t, err)
				return k
			}(),
			scopeId:     "global",
			purpose:     "database",
			rootWrapper: rkw,
			rootKeyId:   rk.PrivateId,
			want:        dkv.Key,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.kms.loadDek(testCtx, tc.scopeId, tc.purpose, tc.rootWrapper, tc.rootKeyId, tc.opt...)
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
			gotKey, err := got.KeyBytes(testCtx)
			assert.Equal(tc.want, gotKey)
		})
	}
}

func TestKms_loadRoot(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	db.Debug(true)
	rk := testRootKey(t, db, "global")

	rkv1, rkw1 := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
	rkv2, rkw2 := testRootKeyVersion(t, db, wrapper, rk.PrivateId)

	tests := []struct {
		name            string
		kms             *Kms
		scopeId         string
		opt             []Option
		want            *multi.PooledWrapper
		wantRootKeyId   string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "missing-scope-id",
			kms: func() *Kms {
				k, err := New(rw, rw, nil)
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing scope id",
		},
		{
			name: "list-keys-error",
			kms: func() *Kms {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("list-keys-error"))
				k, err := New(rw, rw, nil)
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			wantErr:         true,
			wantErrContains: "list-keys-error",
		},
		{
			name: "missing-root-key-for-scope",
			kms: func() *Kms {
				k, err := New(rw, rw, nil)
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "invalid-scope",
			wantErr:         true,
			wantErrIs:       ErrKeyNotFound,
			wantErrContains: "missing root key for scope",
		},
		{
			name: "missing-root-key-wrapper-for-scope",
			kms: func() *Kms {
				k, err := New(rw, rw, nil)
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			wantErr:         true,
			wantErrIs:       ErrKeyNotFound,
			wantErrContains: "missing root key wrapper for scope",
		},
		{
			name: "list-key-version-error",
			kms: func() *Kms {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "root_key_id", "scope_id", "create_time"}).AddRow(rk.PrivateId, rk.PrivateId, "global", time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("list-key-version-error"))
				k, err := New(rw, rw, nil)
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			wantErr:         true,
			wantErrContains: "list-key-version-error",
		},
		{
			name: "list-key-version-no-rows",
			kms: func() *Kms {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "root_key_id", "scope_id", "create_time"}).AddRow(rk.PrivateId, rk.PrivateId, "global", time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "root_key_id", "create_time"}))
				k, err := New(rw, rw, nil)
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			wantErr:         true,
			wantErrContains: "key not found",
		},
		{
			name: "success",
			kms: func() *Kms {
				k, err := New(rw, rw, nil)
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId: "global",
			want: func() *multi.PooledWrapper {
				var pool *multi.PooledWrapper
				for _, wrapper := range []wrapping.Wrapper{rkw1, rkw2} {
					w := aead.NewWrapper()
					keyId, err := wrapper.KeyId(testCtx)
					require.NoError(t, err)
					_, err = w.SetConfig(testCtx, wrapping.WithKeyId(keyId))
					require.NoError(t, err)
					err = w.SetAesGcmKeyBytes([]byte(defaultWrapperSecret))
					require.NoError(t, err)
					switch pool {
					case nil:
						pool, err = multi.NewPooledWrapper(testCtx, w)
						require.NoError(t, err)
					default:
						pool.AddWrapper(testCtx, w)
					}
					require.NoError(t, err)
				}
				return pool
			}(),
			wantRootKeyId: rkv2.RootKeyId,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotWrapper, gotKeyId, err := tc.kms.loadRoot(testCtx, tc.scopeId, tc.opt...)
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
			assert.Equal(tc.want.WrapperForKeyId(rkv1.PrivateId), gotWrapper.WrapperForKeyId(rkv1.PrivateId))
			assert.Equal(tc.want.WrapperForKeyId(rkv2.PrivateId), gotWrapper.WrapperForKeyId(rkv2.PrivateId))
			blob, err := gotWrapper.Encrypt(testCtx, []byte("test"))
			require.NoError(err)
			decrypted, err := tc.want.Decrypt(testCtx, blob)
			require.NoError(err)
			assert.Equal([]byte("test"), decrypted)
			assert.Equal(tc.wantRootKeyId, gotKeyId)
		})
	}
}

func TestKms_KeyId(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	extWrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	repo, err := newRepository(rw, rw)
	require.NoError(err)

	const globalScope = "global"
	databaseKeyPurpose := KeyPurpose("database")

	// Get the global scope's root wrapper
	kmsCache, err := New(rw, rw, []KeyPurpose{"database"})
	require.NoError(err)
	require.NoError(kmsCache.AddExternalWrapper(ctx, KeyPurposeRootKey, extWrapper))
	// Make the global scope base keys
	err = kmsCache.CreateKeysTx(ctx, rand.Reader, globalScope, databaseKeyPurpose)
	require.NoError(err)
	globalRootWrapper, _, err := kmsCache.loadRoot(ctx, globalScope)
	require.NoError(err)

	dks, err := repo.ListDataKeys(ctx)
	require.NoError(err)
	require.Len(dks, 1)

	// Create another key version
	newKeyBytes, err := uuid.GenerateRandomBytes(32)
	require.NoError(err)
	_, err = repo.CreateDataKeyVersion(ctx, globalRootWrapper, dks[0].GetPrivateId(), newKeyBytes)
	require.NoError(err)

	dkvs, err := repo.ListDataKeyVersions(ctx, globalRootWrapper, dks[0].GetPrivateId())
	require.NoError(err)
	require.Len(dkvs, 2)

	keyId1 := dkvs[0].GetPrivateId()
	keyId2 := dkvs[1].GetPrivateId()

	// First test: just getting the key should return the latest
	wrapper, err := kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose)
	require.NoError(err)
	tKeyId, err := wrapper.KeyId(context.Background())
	require.NoError(err)
	require.Equal(keyId2, tKeyId)

	// Second: ask for each in turn
	wrapper, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose, WithKeyId(keyId1))
	require.NoError(err)
	tKeyId, err = wrapper.KeyId(context.Background())
	require.NoError(err)
	require.Equal(keyId1, tKeyId)
	wrapper, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose, WithKeyId(keyId2))
	require.NoError(err)
	tKeyId, err = wrapper.KeyId(context.Background())
	require.NoError(err)
	require.Equal(keyId2, tKeyId)

	// Last: verify something bogus finds nothing
	_, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose, WithKeyId("foo"))
	require.Error(err)

	// empty cache and pull from database
	kmsCache, err = New(rw, rw, []KeyPurpose{"database"})
	require.NoError(err)
	require.NoError(kmsCache.AddExternalWrapper(ctx, KeyPurposeRootKey, extWrapper))
	// ask for each in turn
	wrapper, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose, WithKeyId(keyId1))
	require.NoError(err)
	tKeyId, err = wrapper.KeyId(context.Background())
	require.NoError(err)
	require.Equal(keyId1, tKeyId)
	wrapper, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose, WithKeyId(keyId2))
	require.NoError(err)
	tKeyId, err = wrapper.KeyId(context.Background())
	require.NoError(err)
	require.Equal(keyId2, tKeyId)
}
