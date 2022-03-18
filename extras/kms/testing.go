package kms

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	source "github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/httpfs"
	pgDriver "gorm.io/driver/postgres"

	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"github.com/stretchr/testify/require"
)

// TestRepo returns are test repo
func TestRepo(t *testing.T, db *dbw.DB, opt ...Option) *Repository {
	t.Helper()
	require := require.New(t)
	rw := dbw.New(db)
	r, err := NewRepository(rw, rw, opt...)
	require.NoError(err)
	return r
}

// TestDb will return a test db and a url for that db
func TestDb(t *testing.T) (*dbw.DB, string) {
	return dbw.TestSetup(t, dbw.WithTestMigrationUsingDB(testMigrationFn(t)))
}

// TestMockDb returns a db with an underlying mock.  TODO: can be replaced with
// a similar feature in go-dbw, once this PR is merged:
// https://github.com/hashicorp/go-dbw/pull/16
func TestMockDb(t *testing.T) (*dbw.DB, sqlmock.Sqlmock) {
	t.Helper()
	require := require.New(t)
	db, mock, err := sqlmock.New()
	require.NoError(err)
	require.NoError(err)
	dbw, err := dbw.OpenWith(pgDriver.New(pgDriver.Config{
		Conn: db,
	}))
	require.NoError(err)
	return dbw, mock
}

func testMigrationFn(t *testing.T) func(ctx context.Context, db *sql.DB) error {
	return func(ctx context.Context, db *sql.DB) error {
		t.Helper()
		require := require.New(t)
		var err error
		var dialect string
		var driver database.Driver
		var source source.Driver
		switch strings.ToLower(os.Getenv("DB_DIALECT")) {
		case "postgres":
			dialect = "postgres"
			driver, err = postgres.WithInstance(db, &postgres.Config{})
			require.NoError(err)
			source, err = httpfs.New(http.FS(migrations.PostgresFS), dialect)
			require.NoError(err)
		default:
			dialect = "sqlite"
			driver, err = sqlite.WithInstance(db, &sqlite.Config{})
			require.NoError(err)
			source, err = httpfs.New(http.FS(migrations.SqliteFS), dialect)
			require.NoError(err)
		}
		m, err := migrate.NewWithInstance(
			dialect,
			source,
			dialect,
			driver)
		require.NoError(err)

		err = m.Up()
		require.NoError(err)
		return nil
	}
}
