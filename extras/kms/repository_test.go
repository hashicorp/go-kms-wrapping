package kms_test

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	type args struct {
		r dbw.Reader
		w dbw.Writer
	}
	tests := []struct {
		name            string
		args            args
		want            *kms.Repository
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
			want:    kms.TestRepo(t, db),
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
			wantErrIs:       kms.ErrInvalidParameter,
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
			wantErrIs:       kms.ErrInvalidParameter,
			wantErrContains: "nil reader",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := kms.NewRepository(tc.args.r, tc.args.w)
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
	db, _ := kms.TestDb(t)
	tests := []struct {
		name            string
		repo            *kms.Repository
		wantVersion     string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:        "valid",
			repo:        kms.TestRepo(t, db),
			wantVersion: migrations.Version,
		},
		{
			name: "invalid-version",
			repo: func() *kms.Repository {
				mDb, mock := kms.TestMockDb(t)
				rw := dbw.New(mDb)
				r, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(100))
				return r
			}(),
			wantErr:         true,
			wantErrContains: "invalid version",
		},
		{
			name: "failed-lookup",
			repo: func() *kms.Repository {
				mDb, mock := kms.TestMockDb(t)
				rw := dbw.New(mDb)
				r, err := kms.NewRepository(rw, rw)
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
