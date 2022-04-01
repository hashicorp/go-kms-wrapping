package kms_test

import (
	"context"
	"errors"
	"fmt"
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

func TestRepository_CreateDataKey(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))
	testRepo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	testScopeId := "o_1234567890"
	rk := kms.TestRootKey(t, db, testScopeId)
	rkv, rkvWrapper := kms.TestRootKeyVersion(t, db, wrapper, rk.PrivateId)

	tests := []struct {
		name            string
		repo            *kms.Repository
		purpose         kms.KeyPurpose
		scopeId         string
		key             []byte
		keyWrapper      wrapping.Wrapper
		opt             []kms.Option
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "nil-wrapper",
			repo:            testRepo,
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(kms.DefaultWrapperSecret),
			keyWrapper:      nil,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing key wrapper",
		},
		{
			name:            "missing-purpose",
			repo:            testRepo,
			scopeId:         testScopeId,
			key:             []byte(kms.DefaultWrapperSecret),
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing purpose",
		},
		{
			name:            "missing-key",
			repo:            testRepo,
			purpose:         "database",
			scopeId:         testScopeId,
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing key",
		},
		{
			name:            "empty-key",
			repo:            testRepo,
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(""),
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing key",
		},
		{
			name:            "wrapper-key-id-error",
			repo:            testRepo,
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(kms.DefaultWrapperSecret),
			keyWrapper:      &mockTestWrapper{err: errors.New("KeyId error")},
			wantErr:         true,
			wantErrContains: "KeyId error",
		},
		{
			name:            "wrapper-missing-key-id",
			repo:            testRepo,
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(kms.DefaultWrapperSecret),
			keyWrapper:      aead.NewWrapper(),
			wantErr:         true,
			wantErrContains: "missing root key version id",
		},
		{
			name:            "wrapper-invalid-key-id",
			repo:            testRepo,
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(kms.DefaultWrapperSecret),
			keyWrapper:      &mockTestWrapper{keyId: "invalid-key-id"},
			wantErr:         true,
			wantErrContains: "doesn't start with prefix",
		},
		{
			name:    "encrypt-error",
			repo:    testRepo,
			purpose: "database",
			scopeId: testScopeId,
			key:     []byte(kms.DefaultWrapperSecret),
			keyWrapper: func() wrapping.Wrapper {
				w := aead.NewWrapper()
				w.SetConfig(testCtx, wrapping.WithKeyId(rkv.PrivateId))
				return w
			}(),
			wantErr:         true,
			wantErrContains: "error wrapping value",
		},
		{
			name: "lookup-root-key-version-error",
			repo: func() *kms.Repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("lookup-root-key-version-error"))
				mock.ExpectRollback()
				return r
			}(),
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(kms.DefaultWrapperSecret),
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrContains: "lookup-root-key-version-error",
		},
		{
			name: "create-data-key-error",
			repo: func() *kms.Repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "create_time"}).AddRow(rk.PrivateId, time.Now()))
				mock.ExpectQuery(`INSERT INTO "kms_data_key"`).WillReturnError(errors.New("create-data-key-error"))
				mock.ExpectRollback()
				return r
			}(),
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(kms.DefaultWrapperSecret),
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrContains: "create-data-key-error",
		},
		{
			name: "create-data-key-version-error",
			repo: func() *kms.Repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "root_key_id"}).AddRow(rkv.PrivateId, rkv.RootKeyId))
				mock.ExpectQuery(`INSERT INTO`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "create_time"}).AddRow(rk.PrivateId, time.Now()))
				mock.ExpectQuery(`INSERT INTO`).WillReturnError(errors.New("create-data-key-version-error"))
				mock.ExpectRollback()
				return r
			}(),
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(kms.DefaultWrapperSecret),
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrContains: "create-data-key-version-error",
		},
		{
			name:       "success",
			repo:       testRepo,
			purpose:    "database",
			scopeId:    testScopeId,
			key:        []byte(kms.DefaultWrapperSecret),
			keyWrapper: rkvWrapper,
			wantErr:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			dk, dv, err := tc.repo.CreateDataKey(context.Background(), tc.keyWrapper, tc.purpose, tc.key, tc.opt...)
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
			assert.NotNil(dk.CreateTime)
			foundKey, err := tc.repo.LookupDataKey(context.Background(), dk.PrivateId)
			assert.NoError(err)
			assert.Equal(dk, foundKey)

			assert.NotNil(dv.CreateTime)
			foundKeyVersion, err := tc.repo.LookupDataKeyVersion(context.Background(), tc.keyWrapper, dv.PrivateId)
			assert.NoError(err)
			assert.Equal(dv, foundKeyVersion)
		})
	}
}

func TestRepository_DeleteDatabaseKey(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	testRepo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	const (
		testPurpose = "database"
		testScopeId = "o_1234567890"
	)
	rk := kms.TestRootKey(t, db, testScopeId)

	tests := []struct {
		name            string
		repo            *kms.Repository
		key             *kms.DataKey
		opt             []kms.Option
		wantRowsDeleted int
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "no-private-id",
			key: func() *kms.DataKey {
				k := kms.DataKey{}
				return &k
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "not-found",
			repo: testRepo,
			key: func() *kms.DataKey {
				id, err := dbw.NewId(kms.RootKeyPrefix)
				require.NoError(t, err)
				k := kms.DataKey{}
				k.PrivateId = id
				require.NoError(t, err)
				return &k
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrIs:       kms.ErrRecordNotFound,
			wantErrContains: "not found",
		},
		{
			name: "lookup-by-error",
			key: func() *kms.DataKey {
				id, err := dbw.NewId(kms.RootKeyPrefix)
				require.NoError(t, err)
				k := kms.DataKey{}
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
			key: func() *kms.DataKey {
				id, err := dbw.NewId(kms.RootKeyPrefix)
				require.NoError(t, err)
				k := kms.DataKey{}
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
			key: func() *kms.DataKey {
				id, err := dbw.NewId(kms.RootKeyPrefix)
				require.NoError(t, err)
				k := kms.DataKey{}
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
			key:             kms.TestDataKey(t, db, rk.PrivateId, testPurpose),
			wantRowsDeleted: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deletedRows, err := tc.repo.DeleteDataKey(testCtx, tc.key.PrivateId, tc.opt...)
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
			foundKey, err := tc.repo.LookupDataKey(context.Background(), tc.key.PrivateId)
			assert.Error(err)
			assert.Nil(foundKey)
			assert.ErrorIs(err, kms.ErrRecordNotFound)
		})
	}
}

func TestRepository_ListDataKeys(t *testing.T) {
	const (
		testLimit   = 10
		testPurpose = "database"
		testScopeId = "o_1234567890"
	)
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
		opt             []kms.Option
		createCnt       int
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
			wantErr:   false,
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
			name:      "WithOrderByVersion",
			repo:      testRepo,
			createCnt: testLimit * 5,
			opt:       []kms.Option{kms.WithOrderByVersion(kms.AscendingOrderBy)},
			wantCnt:   testLimit,
		},
		{
			name:      "WithPurpose",
			repo:      testRepo,
			createCnt: testLimit * 5,
			opt:       []kms.Option{kms.WithPurpose("not-found")},
			wantCnt:   0,
		},
		{
			name:      "WithPurpose",
			repo:      testRepo,
			createCnt: testLimit * 5,
			opt:       []kms.Option{kms.WithPurpose(kms.KeyPurpose(fmt.Sprintf("%s-1", testPurpose)))},
			wantCnt:   1,
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
			rk := kms.TestRootKey(t, db, testScopeId)
			_, rkvWrapper := kms.TestRootKeyVersion(t, db, wrapper, rk.PrivateId)
			for i := 0; i < tc.createCnt; i++ {
				_, _, err := testRepo.CreateDataKey(testCtx, rkvWrapper, kms.KeyPurpose(fmt.Sprintf("%s-%d", testPurpose, i)), []byte(kms.DefaultWrapperSecret))
				require.NoError(err)
			}
			got, err := tc.repo.ListDataKeys(context.Background(), tc.opt...)
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

func TestRepository_LookupDataKey(t *testing.T) {
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
		privateKeyId    string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-private-id",
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "missing private id",
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
			name: "success",
			repo: testRepo,
			privateKeyId: func() string {
				id, err := dbw.NewId("o")
				require.NoError(t, err)
				rk := kms.TestRootKey(t, db, id)
				_, rkvWrapper := kms.TestRootKeyVersion(t, db, wrapper, rk.PrivateId)
				dk, _, err := testRepo.CreateDataKey(testCtx, rkvWrapper, "database", []byte(kms.DefaultWrapperSecret))
				require.NoError(t, err)
				return dk.PrivateId
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.repo.LookupDataKey(testCtx, tc.privateKeyId)
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
