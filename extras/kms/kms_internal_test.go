package kms

import (
	"context"
	"crypto/rand"
	"errors"
	"sort"
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
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
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
			got, err := tc.kms.loadDek(testCtx, tc.scopeId, tc.purpose, tc.rootWrapper, tc.rootKeyId)
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
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
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
					err = w.SetAesGcmKeyBytes([]byte(testDefaultWrapperSecret))
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
			gotWrapper, gotKeyId, err := tc.kms.loadRoot(testCtx, tc.scopeId)
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
	extWrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
	repo, err := newRepository(rw, rw)
	require.NoError(err)

	const globalScope = "global"
	databaseKeyPurpose := KeyPurpose("database")

	// Get the global scope's root wrapper
	kmsCache, err := New(rw, rw, []KeyPurpose{databaseKeyPurpose})
	require.NoError(err)
	require.NoError(kmsCache.AddExternalWrapper(ctx, KeyPurposeRootKey, extWrapper))
	// Make the global scope base keys
	err = kmsCache.CreateKeys(ctx, globalScope, []KeyPurpose{databaseKeyPurpose})
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

func TestKms_ClearCache(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	extWrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))

	const (
		globalScope = "global"
		orgScope    = "o_1234567890"
	)
	databaseKeyPurpose := KeyPurpose("database")

	// init kms with a cache
	kmsCache, err := New(rw, rw, []KeyPurpose{"database"}, WithCache(true))
	require.NoError(err)
	require.NoError(kmsCache.AddExternalWrapper(ctx, KeyPurposeRootKey, extWrapper))
	// Make the global scope base keys
	err = kmsCache.CreateKeys(ctx, globalScope, []KeyPurpose{databaseKeyPurpose})
	require.NoError(err)

	// First test: just getting the wrapper
	_, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose)
	require.NoError(err)
	assertCacheEqual(t, 1, kmsCache)

	// delete all the keys
	testDeleteWhere(t, db, &rootKey{}, "1=1")

	// can we still get the wrapper from the cache
	_, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose)
	require.NoError(err)

	require.NoError(kmsCache.ClearCache(ctx))
	assertCacheEqual(t, 0, kmsCache)

	// should now fail to get the wrapper.
	_, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose)
	require.Error(err)

	// Make the global scope base keys again
	err = kmsCache.CreateKeys(ctx, globalScope, []KeyPurpose{databaseKeyPurpose})
	require.NoError(err)
	// add in an org scope
	err = kmsCache.CreateKeys(ctx, orgScope, []KeyPurpose{databaseKeyPurpose})
	require.NoError(err)

	// can we get them...
	globalWrapper, err := kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose)
	require.NoError(err)
	assertCacheEqual(t, 1, kmsCache)

	orgWrapper, err := kmsCache.GetWrapper(ctx, orgScope, databaseKeyPurpose)
	require.NoError(err)
	assertCacheEqual(t, 2, kmsCache)

	assert.NotEqual(t, globalWrapper, orgWrapper)

	kmsCache.ClearCache(ctx, WithScopeIds(orgScope))
	assertCacheEqual(t, 1, kmsCache)

	// re-init kms without a cache
	kmsCache, err = New(rw, rw, []KeyPurpose{"database"})
	require.NoError(err)
	require.NoError(kmsCache.AddExternalWrapper(ctx, KeyPurposeRootKey, extWrapper))
	_, err = kmsCache.GetWrapper(ctx, orgScope, databaseKeyPurpose)
	require.NoError(err)
	assertCacheEqual(t, 0, kmsCache)
	require.NoError(kmsCache.ClearCache(ctx))
}

func TestKms_RotateKeys(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)

	newWrapper := func(id string) wrapping.Wrapper {
		tmpWrapper := aead.NewWrapper()
		_, err := tmpWrapper.SetConfig(testCtx, wrapping.WithKeyId(id))
		require.NoError(t, err)
		key, err := generateKey(testCtx, rand.Reader)
		require.NoError(t, err)
		err = tmpWrapper.SetAesGcmKeyBytes(key)
		require.NoError(t, err)
		return tmpWrapper
	}

	wrapper, err := multi.NewPooledWrapper(testCtx, newWrapper("1"))
	require.NoError(t, err)

	tests := []struct {
		name            string
		kms             *Kms
		scopeId         string
		rewrap          bool
		opt             []Option
		setup           func(k *Kms, scopeId string)
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "missing-scope-id",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database", "auth"})
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
			name: "missing-external-root-wrapper",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			wantErr:         true,
			wantErrIs:       ErrKeyNotFound,
			wantErrContains: "missing external root wrapper",
		},
		{
			name: "scope-root-key-error",
			kms: func() *Kms {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectBegin()
				mock.ExpectExec(`update kms_collection_version`).WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("rotate-key-version-error"))
				k, err := New(rw, rw, []KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			wantErr:         true,
			wantErrContains: "unable to load the scope's root key",
		},
		{
			name: "rewrap-root-key-version-error",
			kms: func() *Kms {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectBegin()
				mock.ExpectExec(`update kms_collection_version`).WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "scope_id", "create_time"}).AddRow("1", "global", time.Now()))
				mock.ExpectQuery(`INSERT`).WillReturnError(errors.New("rewrap-root-key-version-error"))
				k, err := New(rw, rw, []KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			rewrap:          true,
			scopeId:         "global",
			wantErr:         true,
			wantErrContains: "unable to rewrap root key versions",
		},
		{
			name: "rotate-root-key-version-error",
			kms: func() *Kms {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectBegin()
				mock.ExpectExec(`update kms_collection_version`).WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "scope_id", "create_time"}).AddRow("1", "global", time.Now()))
				mock.ExpectQuery(`INSERT`).WillReturnError(errors.New("rotate-root-key-version-error"))
				k, err := New(rw, rw, []KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			scopeId:         "global",
			wantErr:         true,
			wantErrContains: "unable to rotate root key version",
		},
		{
			name:    "success",
			scopeId: "success",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			setup: func(k *Kms, scopeId string) {
				require.NoError(t, k.CreateKeys(testCtx, scopeId, []KeyPurpose{"database", "auth"}))
				_, err := wrapper.SetEncryptingWrapper(testCtx, newWrapper("2"))
				require.NoError(t, err)
			},
		},
		{
			name:    "success-with-rewrap",
			scopeId: "success-with-rewrap",
			rewrap:  true,
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database", "auth"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			setup: func(k *Kms, scopeId string) {
				require.NoError(t, k.CreateKeys(testCtx, scopeId, []KeyPurpose{"database", "auth"}))
				_, err := wrapper.SetEncryptingWrapper(testCtx, newWrapper("3"))
				require.NoError(t, err)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tc.setup != nil {
				tc.setup(tc.kms, tc.scopeId)
			}

			var scopeRootKey *rootKey
			var currentRootKeyVersions []*rootKeyVersion
			var currentDataKeyVersions []*dataKeyVersion
			if !tc.wantErr {
				var err error
				scopeRootKey, err = tc.kms.repo.LookupRootKeyByScope(testCtx, tc.scopeId)
				require.NoError(err)
				currentRootKeyVersions, err = tc.kms.repo.ListRootKeyVersions(testCtx, wrapper, scopeRootKey.PrivateId, withOrderByVersion(ascendingOrderBy))
				require.NoError(err)

				currDataKeys, err := tc.kms.repo.ListDataKeys(testCtx, withRootKeyId(scopeRootKey.PrivateId))
				require.NoError(err)
				for _, dk := range currDataKeys {
					var versions []*dataKeyVersion
					tc.kms.repo.list(testCtx, &versions, "data_key_id = ?", []interface{}{dk.PrivateId}, withOrderByVersion(ascendingOrderBy))
					require.NoError(err)
					currentDataKeyVersions = append(currentDataKeyVersions, versions...)
				}
				sort.Slice(currentDataKeyVersions, func(i, j int) bool {
					return currentDataKeyVersions[i].PrivateId < currentDataKeyVersions[j].PrivateId
				})
			}

			prevVersion, err := currentCollectionVersion(testCtx, rw)
			require.NoError(err)

			tc.opt = append(tc.opt, WithRewrap(tc.rewrap))

			err = tc.kms.RotateKeys(testCtx, tc.scopeId, tc.opt...)
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

			newRootKeyVersions, err := tc.kms.repo.ListRootKeyVersions(testCtx, wrapper, scopeRootKey.PrivateId, withOrderByVersion(ascendingOrderBy))
			require.NoError(err)

			newDataKeys, err := tc.kms.repo.ListDataKeys(testCtx, withRootKeyId(scopeRootKey.PrivateId))
			require.NoError(err)
			var newDataKeyVersions []*dataKeyVersion
			for _, dk := range newDataKeys {
				var versions []*dataKeyVersion
				tc.kms.repo.list(testCtx, &versions, "data_key_id = ?", []interface{}{dk.PrivateId}, withOrderByVersion(ascendingOrderBy))
				require.NoError(err)
				newDataKeyVersions = append(newDataKeyVersions, versions...)
			}
			sort.Slice(newDataKeyVersions, func(i, j int) bool {
				return newDataKeyVersions[i].PrivateId < newDataKeyVersions[j].PrivateId
			})

			assert.Equal(len(newRootKeyVersions), len(currentRootKeyVersions)+1)
			assert.Equal(len(newDataKeyVersions), len(currentDataKeyVersions)*2)

			if tc.rewrap {
				// ensure the rootKeyVersion encrypted keys have been
				// re-encrypted
				for i := range currentRootKeyVersions {
					assert.NotEqual(currentRootKeyVersions[i].CtKey, newRootKeyVersions[i].CtKey)
				}
			}

			currVersion, err := currentCollectionVersion(testCtx, rw)
			require.NoError(err)
			assert.Greater(currVersion, prevVersion)
		})
	}
	t.Run("WithTx", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		db, _ := TestDb(t)
		rw := dbw.New(db)
		purposes := []KeyPurpose{"database"}
		k, err := New(rw, rw, purposes)
		require.NoError(err)
		err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
		require.NoError(err)

		err = k.CreateKeys(testCtx, "global", []KeyPurpose{"database"})
		require.NoError(err)

		tx, err := rw.Begin(testCtx)
		require.NoError(err)

		err = k.RotateKeys(testCtx, "global", WithTx(tx), WithRewrap(true))
		require.NoError(err)

		assert.NoError(tx.Commit(testCtx))

		err = k.RotateKeys(testCtx, "global", WithTx(tx), WithReaderWriter(tx, tx), WithRewrap(true))
		require.Error(err)
		assert.Contains(err.Error(), "WithTx(...) and WithReaderWriter(...) options cannot be used at the same time")
	})
	t.Run("WithTx-missing", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		db, _ := TestDb(t)
		rw := dbw.New(db)
		purposes := []KeyPurpose{"database"}
		k, err := New(rw, rw, purposes)
		require.NoError(err)
		err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
		require.NoError(err)

		err = k.RotateKeys(testCtx, "global", WithTx(rw), WithRewrap(true))
		require.Error(err)
		assert.ErrorIs(err, ErrInvalidParameter)
	})
	t.Run("WithReaderWriter", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		db, _ := TestDb(t)
		rw := dbw.New(db)
		purposes := []KeyPurpose{"database"}
		k, err := New(rw, rw, purposes)
		require.NoError(err)
		err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
		require.NoError(err)

		err = k.CreateKeys(testCtx, "global", []KeyPurpose{"database"})
		require.NoError(err)

		_, err = rw.DoTx(
			context.Background(),
			func(error) bool { return false },
			3, dbw.ExpBackoff{},
			func(r dbw.Reader, w dbw.Writer) error {
				return k.RotateKeys(testCtx, "global", WithReaderWriter(r, w), WithRewrap(true))
			},
		)
		require.NoError(err)

		_, err = rw.DoTx(
			context.Background(),
			func(error) bool { return false },
			3, dbw.ExpBackoff{},
			func(r dbw.Reader, w dbw.Writer) error {
				return k.RotateKeys(testCtx, "global", WithReaderWriter(nil, w), WithRewrap(true))
			},
		)
		require.Error(err)
		assert.Contains(err.Error(), "missing the reader")

		_, err = rw.DoTx(
			context.Background(),
			func(error) bool { return false },
			3, dbw.ExpBackoff{},
			func(r dbw.Reader, w dbw.Writer) error {
				return k.RotateKeys(testCtx, "global", WithReaderWriter(r, nil), WithRewrap(true))
			},
		)
		require.Error(err)
		assert.Contains(err.Error(), "missing the writer")

		_, err = rw.DoTx(
			context.Background(),
			func(error) bool { return false },
			3, dbw.ExpBackoff{},
			func(r dbw.Reader, w dbw.Writer) error {
				return k.RotateKeys(testCtx, "global", WithReaderWriter(r, w), WithTx(rw), WithRewrap(true))
			},
		)
		require.Error(err)
		assert.Contains(err.Error(), "WithTx(...) and WithReaderWriter(...) options cannot be used at the same time")
	})
}

func TestKms_RewrapKeys(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	newWrapper := func(id string) wrapping.Wrapper {
		tmpWrapper := aead.NewWrapper()
		_, err := tmpWrapper.SetConfig(testCtx, wrapping.WithKeyId(id))
		require.NoError(t, err)
		key, err := generateKey(testCtx, rand.Reader)
		require.NoError(t, err)
		err = tmpWrapper.SetAesGcmKeyBytes(key)
		require.NoError(t, err)
		return tmpWrapper
	}

	wrapper, err := multi.NewPooledWrapper(testCtx, newWrapper("1"))
	require.NoError(t, err)
	tests := []struct {
		name            string
		kms             *Kms
		scopeId         string
		opt             []Option
		setup           func(k *Kms, scopeId string)
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "missing-scope-id",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database", "audit"})
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
			name:    "missing-root-wrapper",
			scopeId: "missing-root-wrapper",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database", "audit"})
				require.NoError(t, err)
				return k
			}(),
			wantErr:         true,
			wantErrIs:       ErrKeyNotFound,
			wantErrContains: "unable to get an external root wrapper",
		},
		{
			name:    "bad-txFromOpts",
			scopeId: "bad-txFromOpts",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database", "audit"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			opt:             []Option{WithTx(&dbw.RW{})},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "provided transaction has no inflight transaction",
		},
		{
			name:    "lookupRootKeyByScope-error",
			scopeId: "success",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database", "audit"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			wantErr:         true,
			wantErrIs:       dbw.ErrRecordNotFound,
			wantErrContains: "unable to load the scope's root key",
		},
		{
			name:    "rewrapRootKeyVersionsTx-error",
			scopeId: "success",
			kms: func() *Kms {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectBegin()
				mock.ExpectExec(`update kms_collection_version`).WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "scope_id", "create_time"}).AddRow("1", "global", time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("rewrapRootKeyVersionsTx-error"))
				mock.ExpectRollback()

				k, err := New(rw, rw, []KeyPurpose{"database", "audit"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			wantErr:         true,
			wantErrContains: "unable to rewrap root key versions",
		},
		{
			name:    "success",
			scopeId: "success",
			kms: func() *Kms {
				k, err := New(rw, rw, []KeyPurpose{"database", "audit"})
				require.NoError(t, err)
				err = k.AddExternalWrapper(testCtx, KeyPurposeRootKey, wrapper)
				require.NoError(t, err)
				return k
			}(),
			setup: func(k *Kms, scopeId string) {
				require.NoError(t, k.CreateKeys(testCtx, scopeId, []KeyPurpose{"database", "audit"}))
				_, err := wrapper.SetEncryptingWrapper(testCtx, newWrapper("2"))
				require.NoError(t, err)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tc.setup != nil {
				tc.setup(tc.kms, tc.scopeId)
			}

			prevVersion, err := currentCollectionVersion(testCtx, rw)
			require.NoError(err)

			err = tc.kms.RewrapKeys(testCtx, tc.scopeId, tc.opt...)
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

			currVersion, err := currentCollectionVersion(testCtx, rw)
			require.NoError(err)
			assert.Greater(currVersion, prevVersion)
		})
	}
}

func TestKms_GetWrapper(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	extWrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))

	const globalScope = "global"
	databaseKeyPurpose := KeyPurpose("database")

	// Get the global scope's root wrapper
	kmsCache, err := New(rw, rw, []KeyPurpose{"database"}, WithCache(true))
	require.NoError(err)
	require.NoError(kmsCache.AddExternalWrapper(ctx, KeyPurposeRootKey, extWrapper))
	// Make the global scope base keys
	err = kmsCache.CreateKeys(ctx, globalScope, []KeyPurpose{databaseKeyPurpose})
	require.NoError(err)

	cacheLenFn := func() int {
		var l int
		// should be zero, since the cache is empty
		kmsCache.scopedWrapperCache.Range(func(key, value interface{}) bool {
			l = +1
			return false
		})
		return l
	}
	require.Equal(0, cacheLenFn())
	require.Equal(0, int(kmsCache.collectionVersion))

	gotWrapper, err := kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose)
	require.NoError(err)
	require.NotEmpty(gotWrapper)
	origKeyId, err := gotWrapper.KeyId(ctx)
	require.NoError(err)

	require.Equal(1, cacheLenFn())
	require.Equal(2, int(kmsCache.collectionVersion)) // version starts as 1 in the db... so we're looking for 2

	err = kmsCache.RotateKeys(ctx, globalScope)
	require.NoError(err)

	gotWrapper, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose)
	require.NoError(err)
	require.NotEmpty(gotWrapper)

	require.Equal(1, cacheLenFn())
	require.Equal(3, int(kmsCache.collectionVersion)) // version starts as 1 in the db... so we're looking for 3

	currKeyId, err := gotWrapper.KeyId(ctx)
	require.NoError(err)
	require.NotEqual(origKeyId, currKeyId)
}

func assertCacheEqual(t *testing.T, want int, k *Kms) {
	assert := assert.New(t)
	current := 0
	k.scopedWrapperCache.Range(func(k, v interface{}) bool {
		current++
		return true
	})
	assert.Equal(want, current)
}
