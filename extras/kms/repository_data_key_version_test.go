// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"errors"
	"sort"
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

			prevVersion, err := currentCollectionVersion(testCtx, rw, DefaultTableNamePrefix)
			require.NoError(err)

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

			currVersion, err := currentCollectionVersion(testCtx, rw, DefaultTableNamePrefix)
			require.NoError(err)
			assert.Greater(currVersion, prevVersion)
		})
	}
}

func TestRepository_DeleteDataKeyVersion(t *testing.T) {
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

			prevVersion, err := currentCollectionVersion(testCtx, rw, DefaultTableNamePrefix)
			require.NoError(err)

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

			currVersion, err := currentCollectionVersion(testCtx, rw, DefaultTableNamePrefix)
			require.NoError(err)
			assert.Greater(currVersion, prevVersion)
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
			testDeleteWhere(t, db, func() interface{} { i := dataKeyVersion{tableNamePrefix: DefaultTableNamePrefix}; return &i }(), "1=1")
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
			testDeleteWhere(t, db, func() interface{} { i := dataKeyVersion{tableNamePrefix: DefaultTableNamePrefix}; return &i }(), "1=1")
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
		testDeleteWhere(t, db, func() interface{} { i := dataKeyVersion{tableNamePrefix: DefaultTableNamePrefix}; return &i }(), "1=1")
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

func Test_rotateDataKeyVersionTx(t *testing.T) {
	t.Parallel()
	const (
		testScopeId   = "global"
		testPlainText = "simple plain-text"
	)

	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	rootWrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)
	testKms, err := New(rw, rw, []KeyPurpose{"database"})
	require.NoError(t, err)
	testKms.AddExternalWrapper(testCtx, KeyPurposeRootKey, rootWrapper)
	require.NoError(t, testKms.CreateKeys(testCtx, testScopeId, []KeyPurpose{"database"}))

	rkvWrapper, rootKeyId, err := testKms.loadRoot(testCtx, testScopeId)
	require.NoError(t, err)
	rkvId, err := rkvWrapper.KeyId(testCtx)
	require.NoError(t, err)

	tests := []struct {
		name             string
		reader           dbw.Reader
		writer           dbw.Writer
		repo             *repository
		rootKeyVersionId string
		rkvWrapper       wrapping.Wrapper
		rootKeyId        string
		purpose          KeyPurpose
		opt              []Option
		expectNoRotation bool
		wantErr          bool
		wantErrIs        error
		wantErrContains  string
	}{
		{
			name:             "missing-reader",
			repo:             testRepo,
			writer:           rw,
			rootKeyId:        rootKeyId,
			rkvWrapper:       rkvWrapper,
			rootKeyVersionId: rkvId,
			purpose:          "database",
			wantErr:          true,
			wantErrIs:        ErrInvalidParameter,
			wantErrContains:  "missing reader",
		},
		{
			name:             "missing-writer",
			repo:             testRepo,
			reader:           rw,
			rootKeyId:        rootKeyId,
			rkvWrapper:       rkvWrapper,
			rootKeyVersionId: rkvId,
			purpose:          "database",
			wantErr:          true,
			wantErrIs:        ErrInvalidParameter,
			wantErrContains:  "missing writer",
		},
		{
			name:            "missing-root-key-version-id",
			repo:            testRepo,
			reader:          rw,
			writer:          rw,
			rootKeyId:       rootKeyId,
			rkvWrapper:      rkvWrapper,
			purpose:         "database",
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key version id",
		},
		{
			name:             "missing-root-key-version-wrapper",
			repo:             testRepo,
			reader:           rw,
			writer:           rw,
			rootKeyId:        rootKeyId,
			rootKeyVersionId: rkvId,
			purpose:          "database",
			wantErr:          true,
			wantErrIs:        ErrInvalidParameter,
			wantErrContains:  "missing root key version wrapper",
		},
		{
			name:             "missing-root-key-id",
			repo:             testRepo,
			reader:           rw,
			writer:           rw,
			rootKeyVersionId: rkvId,
			rkvWrapper:       rkvWrapper,
			purpose:          "database",
			wantErr:          true,
			wantErrIs:        ErrInvalidParameter,
			wantErrContains:  "missing root key id",
		},
		{
			name:             "missing-purpose",
			repo:             testRepo,
			reader:           rw,
			writer:           rw,
			rootKeyId:        rootKeyId,
			rootKeyVersionId: rkvId,
			rkvWrapper:       rkvWrapper,
			wantErr:          true,
			wantErrIs:        ErrInvalidParameter,
			wantErrContains:  "missing key purpose",
		},
		{
			name:             "newRepository-error",
			repo:             testRepo,
			reader:           &dbw.RW{},
			writer:           rw,
			rootKeyId:        rootKeyId,
			rootKeyVersionId: rkvId,
			rkvWrapper:       rkvWrapper,
			purpose:          "database",
			wantErr:          true,
			wantErrContains:  "unable to create repo",
		},
		{
			name: "ListDataKeys-error",
			repo: testRepo,
			reader: func() dbw.Reader {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("ListDataKeys-error"))
				return rw
			}(),
			writer:           rw,
			rootKeyId:        rootKeyId,
			rootKeyVersionId: rkvId,
			rkvWrapper:       rkvWrapper,
			purpose:          "database",
			wantErr:          true,
			wantErrContains:  "unable to lookup data key",
		},
		{
			name: "success-ListDataKeys-no-rows",
			repo: testRepo,
			reader: func() dbw.Reader {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}))
				return rw
			}(),
			writer:           rw,
			rootKeyId:        rootKeyId,
			rootKeyVersionId: rkvId,
			rkvWrapper:       rkvWrapper,
			purpose:          "database",
			expectNoRotation: true,
		},
		{
			name: "ListDataKeys-too-many-rows",
			repo: testRepo,
			reader: func() dbw.Reader {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "root_key_id", "purpose", "create_time"}).AddRow("1", "1", "database", time.Now()).AddRow("2", "2", "database", time.Now()))
				return rw
			}(),
			writer:           rw,
			rootKeyId:        rootKeyId,
			rootKeyVersionId: rkvId,
			rkvWrapper:       rkvWrapper,
			purpose:          "database",
			wantErr:          true,
		},
		{
			name:             "randReader-error",
			repo:             testRepo,
			reader:           rw,
			writer:           rw,
			rootKeyId:        rootKeyId,
			rootKeyVersionId: rkvId,
			rkvWrapper:       rkvWrapper,
			purpose:          "database",
			opt:              []Option{WithRandomReader(newMockRandReader(1, "bad-reader"))},
			wantErr:          true,
			wantErrContains:  "bad-reader",
		},
		{
			name:             "Encrypt-error",
			repo:             testRepo,
			reader:           rw,
			writer:           rw,
			rootKeyId:        rootKeyId,
			rootKeyVersionId: rkvId,
			rkvWrapper:       &mockTestWrapper{err: errors.New("Encrypt-error"), encryptError: true},
			purpose:          "database",
			wantErr:          true,
			wantErrContains:  "unable to encrypt new data key version",
		},
		{
			name:             "create-error",
			repo:             testRepo,
			reader:           rw,
			writer:           &dbw.RW{},
			rootKeyId:        rootKeyId,
			rootKeyVersionId: rkvId,
			rkvWrapper:       rkvWrapper,
			purpose:          "database",
			wantErr:          true,
			wantErrContains:  "unable to create data key version",
		},
		{
			name:             "success",
			repo:             testRepo,
			reader:           rw,
			writer:           rw,
			rootKeyId:        rootKeyId,
			rootKeyVersionId: rkvId,
			rkvWrapper:       rkvWrapper,
			purpose:          "database",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			var currentDataKeyVersions []*dataKeyVersion
			var encryptedBlob *wrapping.BlobInfo
			var currentWrapper wrapping.Wrapper
			if !tc.wantErr {
				currDataKeys, err := tc.repo.ListDataKeys(testCtx, withRootKeyId(tc.rootKeyId))
				require.NoError(err)
				for _, dk := range currDataKeys {
					var versions []*dataKeyVersion
					tc.repo.list(testCtx, &versions, "data_key_id = ?", []interface{}{dk.PrivateId}, withOrderByVersion(ascendingOrderBy))
					require.NoError(err)
					currentDataKeyVersions = append(currentDataKeyVersions, versions...)
				}
				sort.Slice(currentDataKeyVersions, func(i, j int) bool {
					return currentDataKeyVersions[i].PrivateId < currentDataKeyVersions[j].PrivateId
				})

				currentWrapper, err = testKms.GetWrapper(testCtx, testScopeId, tc.purpose)
				require.NoError(err)
				encryptedBlob, err = currentWrapper.Encrypt(testCtx, []byte(testPlainText))
				require.NoError(err)

				// rotateDataKeyVersionTx doesn't increment the collection
				// version, so we have to do it here
				err = updateKeyCollectionVersion(testCtx, tc.writer, DefaultTableNamePrefix)
				require.NoError(err)
			}

			err = rotateDataKeyVersionTx(testCtx, tc.reader, tc.writer, DefaultTableNamePrefix, tc.rootKeyVersionId, tc.rkvWrapper, tc.rootKeyId, tc.purpose, tc.opt...)
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

			// ensure we can decrypt something using the rotated wrapper (does
			// the previous key still work)
			rotatedWrapper, err := testKms.GetWrapper(testCtx, testScopeId, tc.purpose)
			require.NoError(err)
			pt, err := rotatedWrapper.Decrypt(testCtx, encryptedBlob)
			require.NoError(err)
			assert.Equal(testPlainText, string(pt))

			newDataKeys, err := tc.repo.ListDataKeys(testCtx, withRootKeyId(tc.rootKeyId))
			require.NoError(err)
			var newDataKeyVersions []*dataKeyVersion
			for _, dk := range newDataKeys {
				var versions []*dataKeyVersion
				tc.repo.list(testCtx, &versions, "data_key_id = ?", []interface{}{dk.PrivateId}, withOrderByVersion(ascendingOrderBy))
				require.NoError(err)
				newDataKeyVersions = append(newDataKeyVersions, versions...)
			}
			sort.Slice(newDataKeyVersions, func(i, j int) bool {
				return newDataKeyVersions[i].PrivateId < newDataKeyVersions[j].PrivateId
			})
			switch {
			case tc.expectNoRotation:
				assert.Equal(len(newDataKeyVersions), len(currentDataKeyVersions))
			default:
				assert.Equal(len(newDataKeyVersions), len(currentDataKeyVersions)*2)
				// encrypt pt with new version and make sure none of the old
				// versions can decrypt it
				encryptedBlob, err = rotatedWrapper.Encrypt(testCtx, []byte(testPlainText))
				require.NoError(err)
				_, err = currentWrapper.Decrypt(testCtx, encryptedBlob)
				assert.Error(err)
			}
		})
	}
}

func Test_rewrapDataKeyVersionsTx(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	rootWrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
	testKms, err := New(rw, rw, []KeyPurpose{"database"})
	require.NoError(t, err)
	testKms.AddExternalWrapper(testCtx, KeyPurposeRootKey, rootWrapper)
	require.NoError(t, testKms.CreateKeys(testCtx, "global", []KeyPurpose{"database"}))

	rkvWrapper, rootKeyId, err := testKms.loadRoot(testCtx, "global")
	require.NoError(t, err)

	tests := []struct {
		name            string
		reader          dbw.Reader
		writer          dbw.Writer
		rkvWrapper      wrapping.Wrapper
		rootKeyId       string
		opt             []Option
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-reader",
			writer:          rw,
			rkvWrapper:      rkvWrapper,
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing reader",
		},
		{
			name:            "missing-writer",
			reader:          rw,
			rkvWrapper:      rkvWrapper,
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing writer",
		},
		{
			name:            "missing-rkvWrapper",
			reader:          rw,
			writer:          rw,
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key version wrapper",
		},
		{
			name:            "missing-rootKeyId",
			reader:          rw,
			writer:          rw,
			rkvWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key id",
		},
		{
			name:            "newRepository-error",
			reader:          &dbw.RW{},
			writer:          rw,
			rootKeyId:       rootKeyId,
			rkvWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrContains: "unable to create repo",
		},
		{
			name: "ListDataKeys-error",
			reader: func() dbw.Reader {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("ListDataKeys-error"))
				return rw
			}(),
			writer:          rw,
			rootKeyId:       rootKeyId,
			rkvWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrContains: "unable to list the current data keys",
		},
		{
			name: "list-error",
			reader: func() dbw.Reader {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"private_id", "root_key_id", "purpose", "create_time"}).AddRow("1", "1", "database", time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("list-error"))
				return rw
			}(),
			writer:          rw,
			rootKeyId:       rootKeyId,
			rkvWrapper:      rkvWrapper,
			wantErr:         true,
			wantErrContains: "unable to list the current data key versions",
		},
		{
			name:            "Decrypt-error",
			reader:          rw,
			writer:          rw,
			rootKeyId:       rootKeyId,
			rkvWrapper:      &mockTestWrapper{err: errors.New("Decrypt-error"), decryptError: true},
			wantErr:         true,
			wantErrContains: "failed to decrypt data key version",
		},
		{
			name:            "Encrypt-error",
			reader:          rw,
			writer:          rw,
			rootKeyId:       rootKeyId,
			rkvWrapper:      &mockTestWrapper{err: errors.New("Encrypt-error"), encryptError: true},
			wantErr:         true,
			wantErrContains: "failed to rewrap data key version",
		},
		{
			name:       "success",
			reader:     rw,
			writer:     rw,
			rkvWrapper: rkvWrapper,
			rootKeyId:  rootKeyId,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			err := rewrapDataKeyVersionsTx(testCtx, tc.reader, tc.writer, DefaultTableNamePrefix, tc.rkvWrapper, tc.rootKeyId, tc.opt...)
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

func TestRepository_ListDataKeyVersionReferencers(t *testing.T) {
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	testRepo, err := newRepository(rw, rw)
	require.NoError(t, err)

	t.Run("No options", func(t *testing.T) {
		tableNames, err := testRepo.ListDataKeyVersionReferencers(context.Background())
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"kms_test_encrypted_data"}, tableNames)
	})
	t.Run("WithTx", func(t *testing.T) {
		tx, err := rw.Begin(context.Background())
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = tx.Rollback(context.Background())
		})
		tableNames, err := testRepo.ListDataKeyVersionReferencers(context.Background(), WithTx(tx))
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"kms_test_encrypted_data"}, tableNames)
		err = tx.Commit(context.Background())
		require.NoError(t, err)
	})

	t.Run("WithReaderWriter", func(t *testing.T) {
		tx, err := rw.Begin(context.Background())
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = tx.Rollback(context.Background())
		})
		tableNames, err := testRepo.ListDataKeyVersionReferencers(context.Background(), WithReaderWriter(tx, tx))
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"kms_test_encrypted_data"}, tableNames)
		err = tx.Commit(context.Background())
		require.NoError(t, err)
	})
}
