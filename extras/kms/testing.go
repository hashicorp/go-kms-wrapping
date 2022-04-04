package kms

import (
	"context"
	"database/sql"
	"fmt"
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
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	pgDriver "gorm.io/driver/postgres"
)

// TestRootKey returns a new test RootKey
func TestRootKey(t *testing.T, conn *dbw.DB, scopeId string) *RootKey {
	t.Helper()
	require := require.New(t)
	rw := dbw.New(conn)
	TestDeleteWhere(t, conn, &RootKey{}, "scope_id = ?", scopeId)
	k, err := NewRootKey(scopeId)
	require.NoError(err)
	id, err := newRootKeyId()
	require.NoError(err)
	k.PrivateId = id
	err = create(context.Background(), rw, k)
	require.NoError(err)
	return k
}

// TestRootKeyVersion returns a new test RootKeyVersion with its associated wrapper
func TestRootKeyVersion(t *testing.T, conn *dbw.DB, wrapper wrapping.Wrapper, rootId string) (kv *RootKeyVersion, kvWrapper wrapping.Wrapper) {
	t.Helper()
	require := require.New(t)
	testCtx := context.Background()
	rw := dbw.New(conn)
	rootKeyVersionWrapper := wrapping.NewTestWrapper([]byte(DefaultWrapperSecret))
	key, err := rootKeyVersionWrapper.KeyBytes(testCtx)
	require.NoError(err)
	k, err := NewRootKeyVersion(rootId, key)
	require.NoError(err)
	id, err := newRootKeyVersionId()
	require.NoError(err)
	k.PrivateId = id
	err = k.Encrypt(context.Background(), wrapper)
	require.NoError(err)
	err = create(context.Background(), rw, k)
	require.NoError(err)
	err = rw.LookupBy(context.Background(), k)
	require.NoError(err)
	rootKeyVersionWrapper.SetConfig(testCtx, wrapping.WithKeyId(k.PrivateId))
	require.NoError(err)
	return k, rootKeyVersionWrapper
}

// TestData returns a new test DataKey
func TestDataKey(t *testing.T, conn *dbw.DB, rootKeyId string, purpose KeyPurpose) *DataKey {
	t.Helper()
	require := require.New(t)
	TestDeleteWhere(t, conn, &DataKey{}, "root_key_id = ?", rootKeyId)
	rw := dbw.New(conn)
	k, err := NewDataKey(rootKeyId, purpose)
	require.NoError(err)
	id, err := newDataKeyId()
	require.NoError(err)
	k.PrivateId = id
	k.RootKeyId = rootKeyId
	err = create(context.Background(), rw, k)
	require.NoError(err)
	return k
}

// TestDataKeyVersion returns a new test DataKeyVersion with its associated wrapper
func TestDataKeyVersion(t *testing.T, conn *dbw.DB, rootKeyVersionWrapper wrapping.Wrapper, dataKeyId string, key []byte) *DataKeyVersion {
	t.Helper()
	require := require.New(t)
	rw := dbw.New(conn)
	rootKeyVersionId, err := rootKeyVersionWrapper.KeyId(context.Background())
	require.NoError(err)
	require.NotEmpty(rootKeyVersionId)
	k, err := NewDataKeyVersion(dataKeyId, key, rootKeyVersionId)
	require.NoError(err)
	id, err := newDataKeyVersionId()
	require.NoError(err)
	k.PrivateId = id
	err = k.Encrypt(context.Background(), rootKeyVersionWrapper)
	require.NoError(err)
	err = create(context.Background(), rw, k)
	require.NoError(err)
	err = rw.LookupBy(context.Background(), k)
	require.NoError(err)
	return k
}

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

// TestDeleteWhere allows you to easily delete resources for testing purposes
// including all the current resources.
func TestDeleteWhere(t *testing.T, conn *dbw.DB, i interface{}, whereClause string, args ...interface{}) {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()
	tabler, ok := i.(interface {
		TableName() string
	})
	require.True(ok)
	_, err := dbw.New(conn).Exec(ctx, fmt.Sprintf(`delete from "%s" where %s`, tabler.TableName(), whereClause), []interface{}{args})
	require.NoError(err)
}
