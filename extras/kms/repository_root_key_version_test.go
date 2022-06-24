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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateRootKeyVersion(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
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

			prevVersion, err := currentCollectionVersion(testCtx, rw)
			require.NoError(err)

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

			currVersion, err := currentCollectionVersion(testCtx, rw)
			require.NoError(err)
			assert.Greater(currVersion, prevVersion)
		})
	}
}

func TestRepository_DeleteRootKeyVersion(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
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

			prevVersion, err := currentCollectionVersion(testCtx, rw)
			require.NoError(err)

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

			currVersion, err := currentCollectionVersion(testCtx, rw)
			require.NoError(err)
			assert.Greater(currVersion, prevVersion)
		})
	}
}

func TestRepository_LatestRootKeyVersion(t *testing.T) {
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
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
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))
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

func Test_rewrapRootKeyVersionsTx(t *testing.T) {
	t.Parallel()
	const (
		globalScope   = "global"
		testPlainText = "simple plain-text"
	)
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
	rootWrapper, err := multi.NewPooledWrapper(testCtx, newWrapper("1"))
	require.NoError(t, err)

	testKms, err := New(rw, rw, []KeyPurpose{"database"})
	require.NoError(t, err)
	testKms.AddExternalWrapper(testCtx, KeyPurposeRootKey, rootWrapper)
	require.NoError(t, testKms.CreateKeys(testCtx, globalScope, []KeyPurpose{"database"}))

	_, rootKeyId, err := testKms.loadRoot(testCtx, globalScope)
	require.NoError(t, err)

	tests := []struct {
		name            string
		reader          dbw.Reader
		writer          dbw.Writer
		rootWrapper     wrapping.Wrapper
		rootKeyId       string
		setup           func()
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-reader",
			writer:          rw,
			rootWrapper:     rootWrapper,
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing reader",
		},
		{
			name:            "missing-writer",
			reader:          rw,
			rootWrapper:     rootWrapper,
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing writer",
		},
		{
			name:            "missing-root-wrapper",
			reader:          rw,
			writer:          rw,
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root wrapper",
		},
		{
			name:            "missing-root-key-id",
			reader:          rw,
			writer:          rw,
			rootWrapper:     rootWrapper,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key id",
		},
		{
			name: "ListRootKeyVersions-error",
			reader: func() dbw.Reader {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("ListRootKeyVersions-error"))
				return rw
			}(),
			writer:          rw,
			rootWrapper:     rootWrapper,
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrContains: "unable to list root key versions",
		},
		{
			name:            "Encrypt-error",
			reader:          rw,
			writer:          rw,
			rootWrapper:     &mockTestWrapper{err: errors.New("Encrypt-error"), encryptError: true},
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrContains: "failed to rewrap root key version",
		},
		{
			name:            "update-error",
			reader:          rw,
			writer:          &dbw.RW{},
			rootKeyId:       rootKeyId,
			rootWrapper:     rootWrapper,
			wantErr:         true,
			wantErrContains: "failed to update root key version",
		},
		{
			name:        "success",
			reader:      rw,
			writer:      rw,
			rootWrapper: rootWrapper,
			rootKeyId:   rootKeyId,
			setup: func() {
				_, err := rootWrapper.SetEncryptingWrapper(testCtx, newWrapper("2"))
				require.NoError(t, err)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tc.setup != nil {
				tc.setup()
			}

			var currentRootKeyVersions []*rootKeyVersion
			var encryptedBlob *wrapping.BlobInfo
			if !tc.wantErr {
				currentRootKeyVersions, err = testKms.repo.ListRootKeyVersions(testCtx, rootWrapper, globalScope, withOrderByVersion(ascendingOrderBy))
				require.NoError(err)

				currentWrapper, _, err := testKms.loadRoot(testCtx, globalScope)
				require.NoError(err)
				encryptedBlob, err = currentWrapper.Encrypt(testCtx, []byte(testPlainText))
				require.NoError(err)
			}

			err := rewrapRootKeyVersionsTx(testCtx, tc.reader, tc.writer, tc.rootWrapper, tc.rootKeyId)
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
			rotatedWrapper, _, err := testKms.loadRoot(testCtx, globalScope)
			require.NoError(err)
			pt, err := rotatedWrapper.Decrypt(testCtx, encryptedBlob)
			require.NoError(err)
			assert.Equal(testPlainText, string(pt))

			newRootKeyVersions, err := testKms.repo.ListRootKeyVersions(testCtx, rootWrapper, globalScope, withOrderByVersion(ascendingOrderBy))
			require.NoError(err)
			for i := range currentRootKeyVersions {
				assert.NotEqual(currentRootKeyVersions[i].CtKey, newRootKeyVersions[i].CtKey)
			}
		})
	}
}

func Test_rotateRootKeyVersionTx(t *testing.T) {
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

	_, rootKeyId, err := testKms.loadRoot(testCtx, testScopeId)
	require.NoError(t, err)

	tests := []struct {
		name            string
		writer          dbw.Writer
		repo            *repository
		rootWrapper     wrapping.Wrapper
		rootKeyId       string
		opt             []Option
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-root-wrapper",
			writer:          rw,
			repo:            testRepo,
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root wrapper",
		},
		{
			name:            "missing-root-key-id",
			writer:          rw,
			repo:            testRepo,
			rootWrapper:     rootWrapper,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root key id",
		},
		{
			name:            "success-missing-writer",
			repo:            testRepo,
			rootWrapper:     rootWrapper,
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing writer",
		},
		{
			name:            "randReader-error",
			writer:          rw,
			repo:            testRepo,
			rootWrapper:     rootWrapper,
			rootKeyId:       rootKeyId,
			opt:             []Option{WithRandomReader(newMockRandReader(1, "bad-reader"))},
			wantErr:         true,
			wantErrContains: "bad-reader",
		},
		{
			name:            "Encrypt-error",
			writer:          rw,
			repo:            testRepo,
			rootWrapper:     &mockTestWrapper{err: errors.New("Encrypt-error"), encryptError: true},
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrContains: "unable to encrypt new root key version",
		},
		{
			name:            "create-error",
			writer:          &dbw.RW{},
			repo:            testRepo,
			rootWrapper:     rootWrapper,
			rootKeyId:       rootKeyId,
			wantErr:         true,
			wantErrContains: "unable to create root key version",
		},
		{
			name:        "success",
			writer:      rw,
			repo:        testRepo,
			rootWrapper: rootWrapper,
			rootKeyId:   rootKeyId,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			var currentRootKeyVersions []*rootKeyVersion
			var currentWrapper *multi.PooledWrapper
			var encryptedBlob *wrapping.BlobInfo
			if !tc.wantErr {
				currentRootKeyVersions, err = tc.repo.ListRootKeyVersions(testCtx, tc.rootWrapper, tc.rootKeyId)
				require.NoError(err)
				sort.Slice(currentRootKeyVersions, func(i, j int) bool {
					return currentRootKeyVersions[i].PrivateId < currentRootKeyVersions[j].PrivateId
				})
				currentWrapper, _, err = testKms.loadRoot(testCtx, testScopeId)
				require.NoError(err)
				encryptedBlob, err = currentWrapper.Encrypt(testCtx, []byte(testPlainText))
				require.NoError(err)
			}

			got, err := rotateRootKeyVersionTx(testCtx, tc.writer, tc.rootWrapper, tc.rootKeyId, tc.opt...)
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

			// ensure we can decrypt something using the rotated wrapper (does
			// the previous key still work)
			rotatedWrapper, _, err := testKms.loadRoot(testCtx, testScopeId)
			require.NoError(err)
			pt, err := rotatedWrapper.Decrypt(testCtx, encryptedBlob)
			require.NoError(err)
			assert.Equal(testPlainText, string(pt))

			// make sure the rotated rkv wasn't in the orig set
			for _, currRkv := range currentRootKeyVersions {
				assert.NotEqual(got, currRkv)
			}

			newRootKeyVersions, err := tc.repo.ListRootKeyVersions(testCtx, tc.rootWrapper, tc.rootKeyId)
			require.NoError(err)
			sort.Slice(newRootKeyVersions, func(i, j int) bool {
				return newRootKeyVersions[i].PrivateId < newRootKeyVersions[j].PrivateId
			})
			assert.Equal(len(newRootKeyVersions), len(currentRootKeyVersions)*2)

			// encrypt pt with new version and make sure none of the old
			// versions can decrypt it
			encryptedBlob, err = rotatedWrapper.Encrypt(testCtx, []byte(testPlainText))
			require.NoError(err)
			_, err = currentWrapper.Decrypt(testCtx, encryptedBlob)
			assert.Error(err)
		})
	}
}
