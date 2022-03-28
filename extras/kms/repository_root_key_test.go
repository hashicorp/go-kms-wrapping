package kms_test

import (
	"context"
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

func TestRepository_CreateRootKey(t *testing.T) {
	t.Parallel()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))
	testRepo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	testScopeId := "o_1234567890"

	type args struct {
	}
	tests := []struct {
		name            string
		repo            *kms.Repository
		scopeId         string
		key             []byte
		keyWrapper      wrapping.Wrapper
		opt             []kms.Option
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-scope",
			repo:            testRepo,
			key:             []byte("empty-scope"),
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing scope",
		},
		{
			name:            "nil-wrapper",
			repo:            testRepo,
			scopeId:         testScopeId,
			key:             []byte("test key"),
			keyWrapper:      nil,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing key wrapper",
		},
		{
			name:            "missing-key",
			repo:            testRepo,
			scopeId:         testScopeId,
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing key",
		},
		{
			name:            "bad-wrapper",
			repo:            testRepo,
			scopeId:         testScopeId,
			key:             []byte("test key"),
			keyWrapper:      aead.NewWrapper(),
			wantErr:         true,
			wantErrContains: "error wrapping value",
		},
		{
			name: "create-rk-error",
			repo: func() *kms.Repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				testRepo, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin()
				mock.ExpectQuery(`INSERT INTO "kms_root_key"`).WillReturnError(errors.New("create-rk-error"))
				mock.ExpectRollback()
				return testRepo
			}(),
			scopeId:         testScopeId,
			key:             []byte("test key"),
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrContains: "create-rk-error",
		},
		{
			name: "create-rkv-error",
			repo: func() *kms.Repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				testRepo, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin()
				mock.ExpectQuery(`INSERT INTO "kms_root_key"`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectQuery(`INSERT INTO "kms_root_key_version"`).WillReturnError(errors.New("create-rkv-error"))
				mock.ExpectRollback()
				return testRepo
			}(),
			scopeId:         testScopeId,
			key:             []byte("test key"),
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrContains: "create-rkv-error",
		},
		{
			name:       "success",
			repo:       testRepo,
			scopeId:    testScopeId,
			key:        []byte("test key"),
			keyWrapper: wrapper,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rk, kv, err := tc.repo.CreateRootKey(context.Background(), tc.keyWrapper, tc.scopeId, tc.key, tc.opt...)
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
			assert.NotNil(rk.CreateTime)
			foundKey, err := tc.repo.LookupRootKey(context.Background(), tc.keyWrapper, rk.PrivateId)
			assert.NoError(err)
			assert.Equal(rk, foundKey)

			assert.NotNil(kv.CreateTime)
			foundKeyVersion, err := tc.repo.LookupRootKeyVersion(context.Background(), tc.keyWrapper, kv.PrivateId)
			assert.NoError(err)
			assert.Equal(kv, foundKeyVersion)
		})
	}
}

func TestRepository_DeleteRootKey(t *testing.T) {
	t.Parallel()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))
	testRepo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	testScopeId := "o_1234567890"

	tests := []struct {
		name            string
		repo            *kms.Repository
		key             *kms.RootKey
		opt             []kms.Option
		wantRowsDeleted int
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "no-private-id",
			repo: testRepo,
			key: func() *kms.RootKey {
				return &kms.RootKey{}
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "not-found",
			repo: testRepo,
			key: func() *kms.RootKey {
				id, err := dbw.NewId(kms.RootKeyPrefix)
				require.NoError(t, err)
				k := kms.RootKey{}
				k.PrivateId = id
				return &k
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrIs:       kms.ErrRecordNotFound,
			wantErrContains: "record not found",
		},
		{
			name: "lookup-by-error",
			key: func() *kms.RootKey {
				id, err := dbw.NewId(kms.RootKeyPrefix)
				require.NoError(t, err)
				k := kms.RootKey{}
				k.PrivateId = id
				require.NoError(t, err)
				return &k
			}(),
			repo: func() *kms.Repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("lookup-by-error"))
				mock.ExpectRollback()
				return r
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrContains: "lookup-by-error",
		},
		{
			name: "delete-error",
			key: func() *kms.RootKey {
				id, err := dbw.NewId(kms.RootKeyPrefix)
				require.NoError(t, err)
				k := kms.RootKey{}
				k.PrivateId = id
				require.NoError(t, err)
				return &k
			}(),
			repo: func() *kms.Repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectBegin()
				mock.ExpectExec(`DELETE`).WillReturnError(errors.New("delete-error"))
				mock.ExpectRollback()
				return r
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrContains: "delete-error",
		},
		{
			name: "delete-too-many-error",
			key: func() *kms.RootKey {
				id, err := dbw.NewId(kms.RootKeyPrefix)
				require.NoError(t, err)
				k := kms.RootKey{}
				k.PrivateId = id
				require.NoError(t, err)
				return &k
			}(),
			repo: func() *kms.Repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectBegin()
				mock.ExpectExec(`DELETE`).WillReturnResult(sqlmock.NewResult(0, 2))
				mock.ExpectRollback()
				return r
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrIs:       kms.ErrMultipleRecords,
			wantErrContains: "multiple records",
		},
		{
			name:            "valid",
			repo:            testRepo,
			key:             kms.TestRootKey(t, db, testScopeId),
			wantRowsDeleted: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deletedRows, err := tc.repo.DeleteRootKey(context.Background(), tc.key.PrivateId, tc.opt...)
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
			assert.Equal(tc.wantRowsDeleted, deletedRows)
			foundKey, err := tc.repo.LookupRootKey(context.Background(), wrapper, tc.key.PrivateId)
			assert.Error(err)
			assert.Nil(foundKey)
			assert.ErrorIs(err, kms.ErrRecordNotFound)
		})
	}
}

func TestRepository_ListRootKeys(t *testing.T) {
	const testLimit = 10
	t.Parallel()
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))
	testRepo, err := kms.NewRepository(rw, rw, kms.WithLimit(testLimit))
	require.NoError(t, err)

	tests := []struct {
		name            string
		repo            *kms.Repository
		createCnt       int
		opt             []kms.Option
		wantCnt         int
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:      "no-limit",
			repo:      testRepo,
			createCnt: testLimit * 2,
			opt:       []kms.Option{kms.WithLimit(-1)},
			wantCnt:   testLimit * 2,
		},
		{
			name:      "default-limit",
			repo:      testRepo,
			createCnt: testLimit + 5,
			wantCnt:   testLimit,
		},
		{
			name:      "custom-limit",
			repo:      testRepo,
			createCnt: testLimit + 1,
			opt:       []kms.Option{kms.WithLimit(3)},
			wantCnt:   3,
			wantErr:   false,
		},
		{
			name:      "ignored-option-WithOrderByVersion",
			repo:      testRepo,
			createCnt: testLimit * 5,
			opt:       []kms.Option{kms.WithOrderByVersion(kms.AscendingOrderBy)},
			wantCnt:   testLimit,
		},
		{
			name: "list-error",
			repo: func() *kms.Repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("list-error"))
				return r
			}(),
			createCnt:       testLimit,
			wantErr:         true,
			wantErrContains: "list-error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			kms.TestDeleteWhere(t, db, func() interface{} { i := kms.RootKey{}; return &i }(), "1=1")
			for i := 0; i < tc.createCnt; i++ {
				id, err := dbw.NewId(kms.RootKeyPrefix)
				require.NoError(err)
				_, _, err = testRepo.CreateRootKey(testCtx, wrapper, id, []byte(kms.DefaultWrapperSecret))
				require.NoError(err)
			}
			got, err := tc.repo.ListRootKeys(context.Background(), tc.opt...)
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
			assert.Equal(tc.wantCnt, len(got))
		})
	}
}

func TestRepository_LookupRootKey(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))
	testRepo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	tests := []struct {
		name            string
		repo            *kms.Repository
		wrapper         wrapping.Wrapper
		privateKeyId    string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-private-id",
			repo:            testRepo,
			wrapper:         wrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "missing-wrapper",
			repo: testRepo,
			privateKeyId: func() string {
				id, err := dbw.NewId("o")
				require.NoError(t, err)
				k := kms.TestRootKey(t, db, id)
				return k.PrivateId
			}(),
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing key wrapper",
		},
		{
			name: "lookup-error",
			repo: func() *kms.Repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("lookup-error"))
				return r
			}(),
			wrapper: wrapper,
			privateKeyId: func() string {
				id, err := dbw.NewId("o")
				require.NoError(t, err)
				k := kms.TestRootKey(t, db, id)
				return k.PrivateId
			}(),
			wantErr:         true,
			wantErrContains: "lookup-error",
		},
		{
			name:    "success",
			repo:    testRepo,
			wrapper: wrapper,
			privateKeyId: func() string {
				id, err := dbw.NewId("o")
				require.NoError(t, err)
				k := kms.TestRootKey(t, db, id)
				return k.PrivateId
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.repo.LookupRootKey(testCtx, tc.wrapper, tc.privateKeyId)
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
			assert.Equal(tc.privateKeyId, got.PrivateId)
		})
	}
}

func TestRepository_LookupRootKeyVersion(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))
	testRepo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	testScopeId := "o_1234567890"
	rk := kms.TestRootKey(t, db, testScopeId)

	tests := []struct {
		name            string
		repo            *kms.Repository
		wrapper         wrapping.Wrapper
		privateKeyId    string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-private-id",
			repo:            testRepo,
			wrapper:         wrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "missing-wrapper",
			repo: testRepo,
			privateKeyId: func() string {
				id, err := dbw.NewId("o")
				require.NoError(t, err)
				k := kms.TestRootKey(t, db, id)
				return k.PrivateId
			}(),
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing key wrapper",
		},
		{
			name: "lookup-error",
			repo: func() *kms.Repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("lookup-error"))
				return r
			}(),
			wrapper: wrapper,
			privateKeyId: func() string {
				id, err := dbw.NewId("o")
				require.NoError(t, err)
				k := kms.TestRootKey(t, db, id)
				return k.PrivateId
			}(),
			wantErr:         true,
			wantErrContains: "lookup-error",
		},
		{
			name:    "bad-wrapper",
			repo:    testRepo,
			wrapper: aead.NewWrapper(),
			privateKeyId: func() string {
				k, _ := kms.TestRootKeyVersion(t, db, wrapper, rk.PrivateId)
				return k.PrivateId
			}(),
			wantErr:         true,
			wantErrContains: "unable to decrypt",
		},
		{
			name:    "success",
			repo:    testRepo,
			wrapper: wrapper,
			privateKeyId: func() string {
				k, _ := kms.TestRootKeyVersion(t, db, wrapper, rk.PrivateId)
				return k.PrivateId
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.repo.LookupRootKeyVersion(testCtx, tc.wrapper, tc.privateKeyId)
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
			assert.Equal(tc.privateKeyId, got.PrivateId)
		})
	}
}
