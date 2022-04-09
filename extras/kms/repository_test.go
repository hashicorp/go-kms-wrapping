package kms

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	type args struct {
		r dbw.Reader
		w dbw.Writer
	}
	tests := []struct {
		name            string
		args            args
		want            *repository
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "valid",
			args: args{
				r: rw,
				w: rw,
			},
			want:    testRepo(t, db),
			wantErr: false,
		},
		{
			name: "nil-writer",
			args: args{
				r: rw,
				w: nil,
			},
			want:            nil,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "nil writer",
		},
		{
			name: "nil-reader",
			args: args{
				r: nil,
				w: rw,
			},
			want:            nil,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "nil reader",
		},
		{
			name: "valid",
			args: args{
				r: func() dbw.Reader {
					db, mock := dbw.TestSetupWithMock(t)
					rw := dbw.New(db)
					mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow("invalid-version", time.Now()))
					return rw
				}(),
				w: rw,
			},
			want:            testRepo(t, db),
			wantErr:         true,
			wantErrIs:       ErrInvalidVersion,
			wantErrContains: "invalid schema version",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newRepository(tc.args.r, tc.args.w)
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

func TestRepository_ValidateVersion(t *testing.T) {
	testCtx := context.Background()
	db, _ := TestDb(t)
	tests := []struct {
		name            string
		repo            *repository
		wantVersion     string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:        "valid",
			repo:        testRepo(t, db),
			wantVersion: migrations.Version,
		},
		{
			name: "invalid-version",
			repo: func() *repository {
				mDb, mock := testMockDb(t)
				rw := dbw.New(mDb)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(100))
				return r
			}(),
			wantErr:         true,
			wantErrContains: "invalid version",
		},
		{
			name: "failed-lookup",
			repo: func() *repository {
				mDb, mock := testMockDb(t)
				rw := dbw.New(mDb)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("failed-lookup"))
				return r
			}(),
			wantErr:         true,
			wantErrContains: "failed-lookup",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			version, err := tc.repo.ValidateSchema(testCtx)
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

type mockRandReader struct {
	readCnt   uint
	errMsg    string
	errOnRead uint
}

func newMockRandReader(errOnRead uint, errMsg string) *mockRandReader {
	return &mockRandReader{
		readCnt:   0,
		errMsg:    errMsg,
		errOnRead: errOnRead,
	}
}

func (m *mockRandReader) Read(p []byte) (n int, err error) {
	m.readCnt++
	if m.readCnt < m.errOnRead {
		return rand.Read(p)
	}
	return 0, errors.New(m.errMsg)
}

func TestRepository_CreateKeysTx(t *testing.T) {
	const testScopeId = "o_1234567890"
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	testRepo, err := newRepository(rw, rw, withLimit(3))
	require.NoError(t, err)
	wrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))

	tests := []struct {
		name            string
		repo            *repository
		rootWrapper     wrapping.Wrapper
		rand            io.Reader
		scopeId         string
		purpose         []KeyPurpose
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-wrapper",
			repo:            testRepo,
			rand:            rand.Reader,
			scopeId:         testScopeId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing root wrapper",
		},
		{
			name:            "missing-random-reader",
			repo:            testRepo,
			rootWrapper:     wrapper,
			scopeId:         testScopeId,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing random reader",
		},
		{
			name:            "missing-scope-id",
			repo:            testRepo,
			rootWrapper:     wrapper,
			rand:            rand.Reader,
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "missing scope id",
		},
		{
			name:            "reserved-purpose",
			repo:            testRepo,
			rootWrapper:     wrapper,
			rand:            rand.Reader,
			scopeId:         testScopeId,
			purpose:         []KeyPurpose{"rootKey", "database"},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "reserved key purpose",
		},
		{
			name:            "dup-purpose",
			repo:            testRepo,
			rootWrapper:     wrapper,
			rand:            rand.Reader,
			scopeId:         testScopeId,
			purpose:         []KeyPurpose{"database", "database"},
			wantErr:         true,
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "duplicate key purpose",
		},
		{
			name:            "gen-root-key-error",
			repo:            testRepo,
			rootWrapper:     wrapper,
			rand:            newMockRandReader(1, "gen-root-key-error"),
			scopeId:         testScopeId,
			purpose:         []KeyPurpose{"database", "session"},
			wantErr:         true,
			wantErrContains: "gen-root-key-error",
		},
		{
			name:            "gen-purpose-key-error",
			repo:            testRepo,
			rootWrapper:     wrapper,
			rand:            newMockRandReader(2, "gen-purpose-key-error"),
			scopeId:         testScopeId,
			purpose:         []KeyPurpose{"database", "session"},
			wantErr:         true,
			wantErrContains: "gen-purpose-key-error",
		},
		{
			name: "createRootKeyTx-error",
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin()
				mock.ExpectQuery(`INSERT INTO "kms_root_key"`).WillReturnError(errors.New("createRootKeyTx-error"))
				mock.ExpectRollback()
				return r
			}(),
			rootWrapper:     wrapper,
			rand:            rand.Reader,
			scopeId:         testScopeId,
			purpose:         []KeyPurpose{"database", "session"},
			wantErr:         true,
			wantErrContains: "createRootKeyTx-error",
		},
		{
			name: "createDataKeyTx-error",
			repo: func() *repository {
				db, mock := dbw.TestSetupWithMock(t)
				rw := dbw.New(db)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version", "create_time"}).AddRow(migrations.Version, time.Now()))
				r, err := newRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectBegin() // rk
				mock.ExpectQuery(`INSERT INTO`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectCommit()
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectBegin() // rkv
				mock.ExpectQuery(`INSERT INTO`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectCommit()
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "create_time"}).AddRow(testScopeId, time.Now()))
				mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("createDataKeyTx-error"))
				return r
			}(),
			rootWrapper:     wrapper,
			rand:            rand.Reader,
			scopeId:         testScopeId,
			purpose:         []KeyPurpose{"database", "session"},
			wantErr:         true,
			wantErrContains: "createDataKeyTx-error",
		},
		{
			name:        "success",
			repo:        testRepo,
			rootWrapper: wrapper,
			rand:        rand.Reader,
			scopeId:     testScopeId,
			purpose:     []KeyPurpose{"database", "session"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			testDeleteWhere(t, db, func() interface{} { i := rootKey{}; return &i }(), "1=1")
			keys, err := tc.repo.CreateKeysTx(context.Background(), tc.rootWrapper, tc.rand, tc.scopeId, tc.purpose...)
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
			assert.NotNil(keys)
		})
	}
}

func TestRepository_DefaultLimit(t *testing.T) {
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	testRepo, err := newRepository(rw, rw, withLimit(3))
	require.NoError(t, err)
	assert.Equal(t, 3, testRepo.DefaultLimit())
}
