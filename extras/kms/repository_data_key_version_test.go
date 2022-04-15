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

func TestRepository_CreateDataKeyVersion(t *testing.T) {
	const (
		testScopeId = "o_1234567890"
		testPurpose = "database"
	)
	t.Parallel()
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)
	rk := testRootKey(t, db, testScopeId)
	rkv, rkvWrapper := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
	dk := testDataKey(t, db, rk.PrivateId, testPurpose)

	tests := []struct {
		name            string
		repo            *repository
		key             []byte
		dataKeyId       string
		keyWrapper      wrapping.Wrapper
		opt             []Option
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "nil-wrapper",
			repo:            testRepo,
			key:             []byte(testDefaultWrapperSecret),
			keyWrapper:      nil,
			dataKeyId:       dk.PrivateId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key version wrapper",
		},
		{
			name:            "missing-data-key-id",
			repo:            testRepo,
			key:             []byte(testDefaultWrapperSecret),
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing data key id",
		},
		{
			name:            "missing-key",
			repo:            testRepo,
			keyWrapper:      rkvWrapper,
			dataKeyId:       dk.PrivateId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key",
		},
		{
			name:            "empty-key",
			repo:            testRepo,
			keyWrapper:      rkvWrapper,
			dataKeyId:       dk.PrivateId,
			key:             []byte(""),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key",
		},
		{
			name:            "wrapper-key-id-error",
			repo:            testRepo,
			keyWrapper:      &mockTestWrapper{err: errors.New("KeyId error")},
			dataKeyId:       dk.PrivateId,
			key:             []byte(testDefaultWrapperSecret),
			wantErr:         true,
			wantErrContains: "KeyId error",
		},
		{
			name:            "missing-root-key-version-id",
			repo:            testRepo,
			keyWrapper:      aead.NewWrapper(),
			dataKeyId:       dk.PrivateId,
			key:             []byte(testDefaultWrapperSecret),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key version id",
		},
		{
			name: "invalid-root-key-version-id",
			repo: testRepo,
			keyWrapper: func() wrapping.Wrapper {
				w := aead.NewWrapper()
				w.SetConfig(testCtx, wrapping.WithKeyId("invalid-root-key-version-id"))
				return w
			}(), dataKeyId: dk.PrivateId,
			key:             []byte(testDefaultWrapperSecret),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "doesn't start with prefix",
		},
		{
			name: "encrypt-error",
			repo: testRepo,
			keyWrapper: func() wrapping.Wrapper {
				w := aead.NewWrapper()
				w.SetConfig(testCtx, wrapping.WithKeyId(rkv.PrivateId))
				return w
			}(), dataKeyId: dk.PrivateId,
			key:             []byte(testDefaultWrapperSecret),
			wantErr:         true,
			wantErrContains: "error wrapping value",
		},
		{
			name: "create-dkv-error",
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				testRepo, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin()
				mock.ExpectQuery(`INSERT INTO "kms_data_key_version"`).WillReturnError(errors.New("create-dkv-error"))
				mock.ExpectRollback()
				return testRepo
			}(),
			key:             []byte(testDefaultWrapperSecret),
			keyWrapper:      rkvWrapper,
			dataKeyId:       dk.PrivateId,
			wantErr:         true,
			wantErrContains: "create-dkv-error",
		},
		{
			name:       "valid",
			repo:       testRepo,
			key:        []byte(testDefaultWrapperSecret),
			keyWrapper: rkvWrapper,
			dataKeyId:  dk.PrivateId,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			k, err := tc.repo.CreateDataKeyVersion(context.Background(), tc.keyWrapper, tc.dataKeyId, tc.key, tc.opt...)
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
			foundKey, err := tc.repo.LookupDataKeyVersion(context.Background(), tc.keyWrapper, k.PrivateId)
			assert.NoError(err)
			assert.Equal(k, foundKey)
		})
	}
}

func TestRepository_DeleteDataKeyVersion(t *testing.T) {
	const (
		testScopeId = "o_1234567890"
		testPurpose = "database"
	)
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)
	rk := testRootKey(t, db, testScopeId)
	_, rkvWrapper := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
	dk := testDataKey(t, db, rk.PrivateId, testPurpose)

	tests := []struct {
		name            string
		repo            *repository
		key             *dataKeyVersion
		opt             []Option
		wantRowsDeleted int
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "no-private-id",
			repo: testRepo,
			key: func() *dataKeyVersion {
				return &dataKeyVersion{}
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "not-found",
			repo: testRepo,
			key: func() *dataKeyVersion {
				id, err := dbw.NewId(dataKeyPrefix)
				require.NoError(t, err)
				k := dataKeyVersion{}
				k.PrivateId = id
				require.NoError(t, err)
				return &k
			}(),
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrIs:       ErrRecordNotFound,
			wantErrContains: "record not found",
		},
		{
			name: "lookup-by-error",
			key:  testDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte(testDefaultWrapperSecret)),
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
			key: func() *dataKeyVersion {
				id, err := dbw.NewId(rootKeyPrefix)
				require.NoError(t, err)
				k := dataKeyVersion{}
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
			key: func() *dataKeyVersion {
				id, err := dbw.NewId(rootKeyPrefix)
				require.NoError(t, err)
				k := dataKeyVersion{}
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
			name:            "success",
			repo:            testRepo,
			key:             testDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte(testDefaultWrapperSecret)),
			wantRowsDeleted: 1,
			wantErr:         false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deletedRows, err := tc.repo.DeleteDataKeyVersion(context.Background(), tc.key.PrivateId, tc.opt...)
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
			foundKey, err := tc.repo.LookupDataKeyVersion(context.Background(), wrapper, tc.key.PrivateId)
			assert.Error(err)
			assert.Nil(foundKey)
			assert.ErrorIs(err, ErrRecordNotFound)
		})
	}
}

func TestRepository_LatestDataKeyVersion(t *testing.T) {
	const (
		testScopeId = "o_1234567890"
		testPurpose = "database"
	)
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)
	rk := testRootKey(t, db, testScopeId)
	_, rkvWrapper := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
	dk := testDataKey(t, db, rk.PrivateId, testPurpose)

	tests := []struct {
		name            string
		repo            *repository
		createCnt       int
		dataKeyId       string
		keyWrapper      wrapping.Wrapper
		wantVersion     uint32
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:        "5",
			repo:        testRepo,
			dataKeyId:   dk.PrivateId,
			createCnt:   5,
			keyWrapper:  rkvWrapper,
			wantVersion: 5,
		},
		{
			name:        "1",
			repo:        testRepo,
			dataKeyId:   dk.PrivateId,
			createCnt:   1,
			keyWrapper:  rkvWrapper,
			wantVersion: 1,
		},
		{
			name:            "0",
			repo:            testRepo,
			dataKeyId:       dk.PrivateId,
			createCnt:       0,
			keyWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrIs:       ErrRecordNotFound,
			wantErrContains: "not found",
		},
		{
			name:            "missing-data-key-id",
			repo:            testRepo,
			createCnt:       5,
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing data key id",
		},
		{
			name:            "nil-wrapper",
			repo:            testRepo,
			dataKeyId:       dk.PrivateId,
			createCnt:       5,
			keyWrapper:      nil,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key version wrapper",
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
			dataKeyId:       dk.PrivateId,
			createCnt:       5,
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrContains: "search-error",
		},
		{
			name:            "bad-wrapper",
			repo:            testRepo,
			dataKeyId:       dk.PrivateId,
			createCnt:       5,
			keyWrapper:      aead.NewWrapper(),
			wantErr:         true,
			wantErrContains: "error unwrapping value",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testDeleteWhere(t, db, func() interface{} { i := dataKeyVersion{}; return &i }(), "1=1")
			testKeys := []*dataKeyVersion{}
			for i := 0; i < tc.createCnt; i++ {
				k := testDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte("test key"))
				testKeys = append(testKeys, k)
			}
			assert.Equal(tc.createCnt, len(testKeys))
			got, err := tc.repo.LatestDataKeyVersion(context.Background(), tc.keyWrapper, tc.dataKeyId)
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

func TestRepository_ListDataKeyVersions(t *testing.T) {
	const (
		testLimit   = 10
		testPurpose = "database"
		testScopeId = "o_1234567890"
	)
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
	testRepo, err := newRepository(rw, rw, withLimit(testLimit))
	require.NoError(t, err)
	rk := testRootKey(t, db, testScopeId)
	_, rkvWrapper := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
	dk := testDataKey(t, db, rk.PrivateId, testPurpose)

	tests := []struct {
		name            string
		repo            *repository
		dataKeyId       string
		keyWrapper      wrapping.Wrapper
		opt             []Option
		createCnt       int
		wantCnt         int
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:       "no-limit",
			repo:       testRepo,
			createCnt:  testLimit * 2,
			dataKeyId:  dk.PrivateId,
			keyWrapper: rkvWrapper,
			opt:        []Option{withLimit(-1)},
			wantCnt:    testLimit * 2,
		},
		{
			name:       "default-limit",
			repo:       testRepo,
			createCnt:  testLimit + 1,
			keyWrapper: rkvWrapper,
			dataKeyId:  dk.PrivateId,
			wantCnt:    testLimit,
		},
		{
			name:       "custom-limit",
			repo:       testRepo,
			createCnt:  testLimit + 1,
			keyWrapper: rkvWrapper,
			dataKeyId:  dk.PrivateId,
			opt:        []Option{withLimit(3)},
			wantCnt:    3,
		},
		{
			name:            "bad-wrapper",
			repo:            testRepo,
			createCnt:       1,
			keyWrapper:      aead.NewWrapper(),
			dataKeyId:       dk.PrivateId,
			wantErr:         true,
			wantErrContains: "error decrypting",
		},
		{
			name:            "missing-data-key-id",
			repo:            testRepo,
			createCnt:       1,
			keyWrapper:      wrapper,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing data key id",
		},
		{
			name:            "missing-wrapper",
			repo:            testRepo,
			createCnt:       1,
			keyWrapper:      nil,
			dataKeyId:       dk.PrivateId,
			wantCnt:         0,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key version wrapper",
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
			dataKeyId:       dk.PrivateId,
			createCnt:       testLimit,
			wantErr:         true,
			wantErrContains: "list-error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testDeleteWhere(t, db, func() interface{} { i := dataKeyVersion{}; return &i }(), "1=1")
			keyVersions := []*dataKeyVersion{}
			for i := 0; i < tc.createCnt; i++ {
				k := testDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte("data key"))
				keyVersions = append(keyVersions, k)
			}
			assert.Equal(tc.createCnt, len(keyVersions))
			got, err := tc.repo.ListDataKeyVersions(context.Background(), tc.keyWrapper, tc.dataKeyId, tc.opt...)
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
	t.Run("order-by", func(t *testing.T) {
		const createCnt = 10
		assert, require := assert.New(t), require.New(t)
		testDeleteWhere(t, db, func() interface{} { i := dataKeyVersion{}; return &i }(), "1=1")
		keyVersions := []*dataKeyVersion{}
		for i := 0; i < createCnt; i++ {
			k := testDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte("data key"))
			keyVersions = append(keyVersions, k)
		}
		assert.Equal(createCnt, len(keyVersions))
		got, err := testRepo.ListDataKeyVersions(context.Background(), wrapper, dk.PrivateId, withOrderByVersion(descendingOrderBy))
		require.NoError(err)
		assert.NotNil(got)
		lastVersion := -1
		for _, dkv := range got {
			if lastVersion != -1 {
				currentVersion := dkv.Version
				assert.Greater(lastVersion, lastVersion)
				lastVersion = int(currentVersion)
			}
		}

		got, err = testRepo.ListDataKeyVersions(context.Background(), wrapper, dk.PrivateId, withOrderByVersion(ascendingOrderBy))
		require.NoError(err)
		assert.NotNil(got)
		lastVersion = -1
		for _, dkv := range got {
			if lastVersion != -1 {
				currentVersion := dkv.Version
				assert.Less(lastVersion, lastVersion)
				lastVersion = int(currentVersion)
			}
		}
	})
}

func TestRepository_LookupDataKeyVersion(t *testing.T) {
	const (
		testPurpose = "database"
		testScopeId = "o_1234567890"
	)
	t.Parallel()
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)
	rk := testRootKey(t, db, testScopeId)
	_, rkvWrapper := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
	dk := testDataKey(t, db, rk.PrivateId, testPurpose)
	tests := []struct {
		name            string
		repo            *repository
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
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing private id",
		},
		{
			name: "missing-wrapper",
			repo: testRepo,
			privateKeyId: func() string {
				id, err := dbw.NewId("o")
				require.NoError(t, err)
				k := testRootKey(t, db, id)
				return k.PrivateId
			}(),
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing key wrapper",
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
			wrapper: wrapper,
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
			name:    "bad-wrapper",
			repo:    testRepo,
			wrapper: aead.NewWrapper(),
			privateKeyId: func() string {
				k := testDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte("data key"))
				return k.PrivateId
			}(),
			wantErr:         true,
			wantErrContains: "error unwrapping value",
		},
		{
			name:    "success",
			repo:    testRepo,
			wrapper: wrapper,
			privateKeyId: func() string {
				k := testDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte("data key"))
				return k.PrivateId
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.repo.LookupDataKeyVersion(testCtx, tc.wrapper, tc.privateKeyId)
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
