package kms

import (
	"context"
	"errors"
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

func TestRepository_CreateRootKeyVersion(t *testing.T) {
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)
	testScopeId := "o_1234567890"
	rk := testRootKey(t, db, testScopeId)

	tests := []struct {
		name            string
		repo            *repository
		rootKeyId       string
		key             []byte
		keyWrapper      wrapping.Wrapper
		opt             []Option
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-root-key-id",
			repo:            testRepo,
			keyWrapper:      wrapper,
			key:             []byte("test key"),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key id",
		},
		{
			name:            "missing-wrapper",
			repo:            testRepo,
			rootKeyId:       rk.PrivateId,
			key:             []byte("test key"),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key wrapper",
		},
		{
			name:            "missing-key",
			repo:            testRepo,
			rootKeyId:       rk.PrivateId,
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key",
		},
		{
			name:            "bad-wrapper-fails-encrypt",
			repo:            testRepo,
			rootKeyId:       rk.PrivateId,
			keyWrapper:      aead.NewWrapper(),
			key:             []byte("test key"),
			wantErr:         true,
			wantErrContains: "unable to encrypt",
		},
		{
			name: "create-rkv-error",
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				testRepo, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin()
				mock.ExpectQuery(`INSERT INTO "kms_root_key_version"`).WillReturnError(errors.New("create-rkv-error"))
				mock.ExpectRollback()
				return testRepo
			}(),
			rootKeyId:       rk.PrivateId,
			keyWrapper:      wrapper,
			key:             []byte("test key"),
			wantErr:         true,
			wantErrContains: "create-rkv-error",
		},
		{
			name:       "valid",
			repo:       testRepo,
			rootKeyId:  rk.PrivateId,
			keyWrapper: wrapper,
			key:        []byte("test key"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			k, err := tc.repo.CreateRootKeyVersion(context.Background(), tc.keyWrapper, tc.rootKeyId, tc.key, tc.opt...)
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
			assert.NotNil(k.CreateTime)
			assert.Equal(uint32(1), k.Version)
			foundKey, err := tc.repo.LookupRootKeyVersion(context.Background(), tc.keyWrapper, k.PrivateId)
			assert.NoError(err)
			assert.Equal(k, foundKey)
		})
	}
}

func TestRepository_DeleteRootKeyVersion(t *testing.T) {
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)
	testScopeId := "o_1234567890"
	rk := testRootKey(t, db, testScopeId)

	tests := []struct {
		name            string
		repo            *repository
		key             *rootKeyVersion
		opt             []Option
		wantRowsDeleted int
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "missing-private-id",
			repo: testRepo,
			key: func() *rootKeyVersion {
				return &rootKeyVersion{}
			}(),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "not-found",
			repo: testRepo,
			key: func() *rootKeyVersion {
				id, err := dbw.NewId(rootKeyPrefix)
				require.NoError(t, err)
				k := rootKeyVersion{}
				k.PrivateId = id
				return &k
			}(),
			wantErr:         true,
			wantErrIs:       ErrRecordNotFound,
			wantErrContains: "record not found",
		},
		{
			name: "lookup-by-error",
			key: func() *rootKeyVersion {
				id, err := dbw.NewId(rootKeyPrefix)
				require.NoError(t, err)
				k := rootKeyVersion{}
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
			key: func() *rootKeyVersion {
				id, err := dbw.NewId(rootKeyPrefix)
				require.NoError(t, err)
				k := rootKeyVersion{}
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
			key: func() *rootKeyVersion {
				id, err := dbw.NewId(rootKeyPrefix)
				require.NoError(t, err)
				k := rootKeyVersion{}
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
			name: "valid",
			repo: testRepo,
			key: func() *rootKeyVersion {
				k, _ := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
				return k
			}(),
			wantRowsDeleted: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deletedRows, err := tc.repo.DeleteRootKeyVersion(context.Background(), tc.key.PrivateId, tc.opt...)
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
			foundKey, err := tc.repo.LookupRootKeyVersion(context.Background(), wrapper, tc.key.PrivateId)
			assert.Error(err)
			assert.Nil(foundKey)
			assert.ErrorIs(err, ErrRecordNotFound)
		})
	}
}

func TestRepository_LatestRootKeyVersion(t *testing.T) {
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)
	testScopeId := "o_1234567890"
	rk := testRootKey(t, db, testScopeId)

	tests := []struct {
		name            string
		repo            *repository
		createCnt       int
		rootKeyId       string
		keyWrapper      wrapping.Wrapper
		wantVersion     uint32
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:        "5",
			repo:        testRepo,
			createCnt:   5,
			rootKeyId:   rk.PrivateId,
			keyWrapper:  wrapper,
			wantVersion: 5,
		},
		{
			name:        "1",
			repo:        testRepo,
			createCnt:   1,
			rootKeyId:   rk.PrivateId,
			keyWrapper:  wrapper,
			wantVersion: 1,
		},
		{
			name:            "0",
			repo:            testRepo,
			createCnt:       0,
			rootKeyId:       rk.PrivateId,
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrIs:       ErrRecordNotFound,
			wantErrContains: "record not found",
		},
		{
			name:            "missing-root-key-id",
			repo:            testRepo,
			createCnt:       5,
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key id",
		},
		{
			name:            "nil-wrapper",
			repo:            testRepo,
			createCnt:       5,
			rootKeyId:       rk.PrivateId,
			keyWrapper:      nil,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key wrapper",
		},
		{
			name: "search-error",
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("search-error"))
				return r
			}(),
			createCnt:       5,
			rootKeyId:       rk.PrivateId,
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrContains: "search-error",
		},
		{
			name:            "bad-wrapper",
			repo:            testRepo,
			createCnt:       5,
			rootKeyId:       rk.PrivateId,
			keyWrapper:      aead.NewWrapper(),
			wantErr:         true,
			wantErrContains: "unable to decrypt",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testDeleteWhere(t, db, func() interface{} { i := rootKeyVersion{}; return &i }(), "1=1")
			testKeys := []*rootKeyVersion{}
			for i := 0; i < tc.createCnt; i++ {
				k, _ := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
				testKeys = append(testKeys, k)
			}
			assert.Equal(tc.createCnt, len(testKeys))
			got, err := tc.repo.LatestRootKeyVersion(context.Background(), tc.keyWrapper, tc.rootKeyId)
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
			require.NotNil(got)
			assert.Equal(tc.wantVersion, got.Version)
		})
	}
}

func TestRepository_ListRootKeyVersions(t *testing.T) {
	const testLimit = 10
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	testRepo, err := newRepository(rw, rw, withLimit(testLimit))
	require.NoError(t, err)
	testScopeId := "o_1234567890"
	rk := testRootKey(t, db, testScopeId)

	tests := []struct {
		name            string
		repo            *repository
		createCnt       int
		rootKeyId       string
		keyWrapper      wrapping.Wrapper
		opt             []Option
		wantCnt         int
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:       "no-limit",
			repo:       testRepo,
			createCnt:  testLimit * 2,
			rootKeyId:  rk.PrivateId,
			keyWrapper: wrapper,
			opt:        []Option{withLimit(-1)},
			wantCnt:    testLimit * 2,
		},
		{
			name:       "default-limit",
			repo:       testRepo,
			createCnt:  testLimit + 1,
			keyWrapper: wrapper,
			rootKeyId:  rk.PrivateId,
			wantCnt:    testLimit,
			wantErr:    false,
		},
		{
			name:       "custom-limit",
			repo:       testRepo,
			createCnt:  testLimit + 1,
			keyWrapper: wrapper,
			rootKeyId:  rk.PrivateId,
			opt:        []Option{withLimit(3)},
			wantCnt:    3,
			wantErr:    false,
		},
		{
			name:            "bad-wrapper",
			repo:            testRepo,
			createCnt:       1,
			keyWrapper:      aead.NewWrapper(),
			rootKeyId:       rk.PrivateId,
			wantErr:         true,
			wantErrContains: "unable to decrypt",
		},
		{
			name:            "missing-root-key-id",
			repo:            testRepo,
			createCnt:       1,
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key id",
		},
		{
			name:            "missing-wrapper",
			repo:            testRepo,
			createCnt:       1,
			keyWrapper:      nil,
			rootKeyId:       rk.PrivateId,
			wantCnt:         0,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key wrapper",
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
			keyWrapper:      wrapper,
			rootKeyId:       rk.PrivateId,
			createCnt:       testLimit,
			wantErr:         true,
			wantErrContains: "list-error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testDeleteWhere(t, db, func() interface{} { i := rootKeyVersion{}; return &i }(), "1=1")
			testRootKeyVersions := []*rootKeyVersion{}
			for i := 0; i < tc.createCnt; i++ {
				k, _ := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
				testRootKeyVersions = append(testRootKeyVersions, k)
			}
			assert.Equal(tc.createCnt, len(testRootKeyVersions))
			got, err := tc.repo.ListRootKeyVersions(context.Background(), tc.keyWrapper, tc.rootKeyId, tc.opt...)
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
