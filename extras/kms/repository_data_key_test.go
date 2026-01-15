// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTestWrapper struct {
	wrapping.Wrapper
	decryptError bool
	encryptError bool
	err          error
	keyId        string
}

func (m *mockTestWrapper) KeyId(context.Context) (string, error) {
	if m.err != nil && !m.encryptError && !m.decryptError {
		return "", m.err
	}
	return m.keyId, nil
}

func (m *mockTestWrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if m.err != nil && m.encryptError {
		return nil, m.err
	}
	panic("todo")
}

func (m *mockTestWrapper) Decrypt(ctx context.Context, ciphertext *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	if m.err != nil && m.decryptError {
		return nil, m.err
	}
	return []byte("decrypted"), nil
}

func TestRepository_CreateDataKey(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)
	testScopeId := "o_1234567890"
	rk := testRootKey(t, db, testScopeId)
	rkv, rkvWrapper := testRootKeyVersion(t, db, wrapper, rk.PrivateId)

	tests := []struct {
		name            string
		repo            *repository
		purpose         KeyPurpose
		scopeId         string
		key             []byte
		keyWrapper      wrapping.Wrapper
		opt             []Option
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "nil-wrapper",
			repo:            testRepo,
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(testDefaultWrapperSecret),
			keyWrapper:      nil,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key wrapper",
		},
		{
			name:            "missing-purpose",
			repo:            testRepo,
			scopeId:         testScopeId,
			key:             []byte(testDefaultWrapperSecret),
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing purpose",
		},
		{
			name:            "missing-key",
			repo:            testRepo,
			purpose:         "database",
			scopeId:         testScopeId,
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
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
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key",
		},
		{
			name:            "wrapper-key-id-error",
			repo:            testRepo,
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(testDefaultWrapperSecret),
			keyWrapper:      &mockTestWrapper{err: errors.New("KeyId error")},
			wantErr:         true,
			wantErrContains: "KeyId error",
		},
		{
			name:            "wrapper-missing-key-id",
			repo:            testRepo,
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(testDefaultWrapperSecret),
			keyWrapper:      aead.NewWrapper(),
			wantErr:         true,
			wantErrContains: "missing root key version id",
		},
		{
			name:            "wrapper-invalid-key-id",
			repo:            testRepo,
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(testDefaultWrapperSecret),
			keyWrapper:      &mockTestWrapper{keyId: "invalid-key-id"},
			wantErr:         true,
			wantErrContains: "doesn't start with prefix",
		},
		{
			name:    "encrypt-error",
			repo:    testRepo,
			purpose: "database",
			scopeId: testScopeId,
			key:     []byte(testDefaultWrapperSecret),
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
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("lookup-root-key-version-error"))
				mock.ExpectRollback()
				return r
			}(),
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(testDefaultWrapperSecret),
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrContains: "lookup-root-key-version-error",
		},
		{
			name: "create-data-key-error",
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin()
				mock.ExpectExec(`update kms_collection_version`).WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "create_time"}).AddRow(rk.PrivateId, time.Now()))
				mock.ExpectQuery(`INSERT INTO "kms_data_key"`).WillReturnError(errors.New("create-data-key-error"))
				mock.ExpectRollback()
				return r
			}(),
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(testDefaultWrapperSecret),
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrContains: "create-data-key-error",
		},
		{
			name: "create-data-key-version-error",
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin()
				mock.ExpectExec(`update kms_collection_version`).WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "root_key_id"}).AddRow(rkv.PrivateId, rkv.RootKeyId))
				mock.ExpectQuery(`INSERT INTO`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "create_time"}).AddRow(rk.PrivateId, time.Now()))
				mock.ExpectQuery(`INSERT INTO`).WillReturnError(errors.New("create-data-key-version-error"))
				mock.ExpectRollback()
				return r
			}(),
			purpose:         "database",
			scopeId:         testScopeId,
			key:             []byte(testDefaultWrapperSecret),
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrContains: "create-data-key-version-error",
		},
		{
			name:       "success",
			repo:       testRepo,
			purpose:    "database",
			scopeId:    testScopeId,
			key:        []byte(testDefaultWrapperSecret),
			keyWrapper: rkvWrapper,
			wantErr:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			prevVersion, err := currentCollectionVersion(testCtx, rw, DefaultTableNamePrefix)
			require.NoError(err)

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

			currVersion, err := currentCollectionVersion(testCtx, rw, DefaultTableNamePrefix)
			require.NoError(err)
			assert.Greater(currVersion, prevVersion)
		})
	}
}

func TestRepository_DeleteDatabaseKey(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)
	const (
		testPurpose = "database"
		testScopeId = "o_1234567890"
	)
	rk := testRootKey(t, db, testScopeId)

	tests := []struct {
		name            string
		repo            *repository
		key             *dataKey
		opt             []Option
		wantRowsDeleted int
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "no-private-id",
			key: func() *dataKey {
				k := dataKey{}
				return &k
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "not-found",
			repo: testRepo,
			key: func() *dataKey {
				id, err := dbw.NewId(rootKeyPrefix)
				require.NoError(t, err)
				k := dataKey{}
				k.PrivateId = id
				require.NoError(t, err)
				return &k
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrIs:       ErrRecordNotFound,
			wantErrContains: "not found",
		},
		{
			name: "lookup-by-error",
			key: func() *dataKey {
				id, err := dbw.NewId(rootKeyPrefix)
				require.NoError(t, err)
				k := dataKey{}
				k.PrivateId = id
				require.NoError(t, err)
				return &k
			}(),
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
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
			key: func() *dataKey {
				id, err := dbw.NewId(rootKeyPrefix)
				require.NoError(t, err)
				k := dataKey{}
				k.PrivateId = id
				require.NoError(t, err)
				return &k
			}(),
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectBegin()
				mock.ExpectExec(`update kms_collection_version`).WillReturnResult(sqlmock.NewResult(1, 1))
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
			key: func() *dataKey {
				id, err := dbw.NewId(rootKeyPrefix)
				require.NoError(t, err)
				k := dataKey{}
				k.PrivateId = id
				require.NoError(t, err)
				return &k
			}(),
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectBegin()
				mock.ExpectExec(`update kms_collection_version`).WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec(`DELETE`).WillReturnResult(sqlmock.NewResult(0, 2))
				mock.ExpectRollback()
				return r
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrIs:       ErrMultipleRecords,
			wantErrContains: "multiple records",
		},
		{
			name:            "valid",
			repo:            testRepo,
			key:             testDataKey(t, db, rk.PrivateId, testPurpose),
			wantRowsDeleted: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			prevVersion, err := currentCollectionVersion(testCtx, rw, DefaultTableNamePrefix)
			require.NoError(err)

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
			assert.ErrorIs(err, ErrRecordNotFound)

			currVersion, err := currentCollectionVersion(testCtx, rw, DefaultTableNamePrefix)
			require.NoError(err)
			assert.Greater(currVersion, prevVersion)
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
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
	testRepo, err := newRepository(rw, rw, withLimit(testLimit))
	require.NoError(t, err)

	tests := []struct {
		name            string
		repo            *repository
		opt             []Option
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
			opt:       []Option{withLimit(-1)},
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
			opt:       []Option{withLimit(3)},
			wantCnt:   3,
			wantErr:   false,
		},
		{
			name:      "WithOrderByVersion",
			repo:      testRepo,
			createCnt: testLimit * 5,
			opt:       []Option{withOrderByVersion(ascendingOrderBy)},
			wantCnt:   testLimit,
		},
		{
			name:      "WithPurpose",
			repo:      testRepo,
			createCnt: testLimit * 5,
			opt:       []Option{withPurpose("not-found")},
			wantCnt:   0,
		},
		{
			name:      "WithPurpose",
			repo:      testRepo,
			createCnt: testLimit * 5,
			opt:       []Option{withPurpose(KeyPurpose(fmt.Sprintf("%s-1", testPurpose)))},
			wantCnt:   1,
		},
		{
			name: "list-error",
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
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
			testDeleteWhere(t, db, func() interface{} { i := rootKey{tableNamePrefix: DefaultTableNamePrefix}; return &i }(), "1=1")
			rk := testRootKey(t, db, testScopeId)
			_, rkvWrapper := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
			for i := 0; i < tc.createCnt; i++ {
				_, _, err := testRepo.CreateDataKey(testCtx, rkvWrapper, KeyPurpose(fmt.Sprintf("%s-%d", testPurpose, i)), []byte(testDefaultWrapperSecret))
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
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)
	tests := []struct {
		name            string
		repo            *repository
		privateKeyId    string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-private-id",
			repo:            testRepo,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "lookup-error",
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("lookup-error"))
				return r
			}(),
			privateKeyId: func() string {
				id, err := dbw.NewId("o")
				require.NoError(t, err)
				k := testRootKey(t, db, id)
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
				rk := testRootKey(t, db, id)
				_, rkvWrapper := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
				dk, _, err := testRepo.CreateDataKey(testCtx, rkvWrapper, "database", []byte(testDefaultWrapperSecret))
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
