package kms

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

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
)

// testRootKey returns a new test RootKey
func testRootKey(t *testing.T, conn *dbw.DB, scopeId string) *rootKey {
	t.Helper()
	require := require.New(t)
	rw := dbw.New(conn)
	testDeleteWhere(t, conn, &rootKey{}, "scope_id = ?", scopeId)
	k, err := newRootKey(scopeId)
	require.NoError(err)
	id, err := newRootKeyId()
	require.NoError(err)
	k.PrivateId = id
	err = create(context.Background(), rw, k)
	require.NoError(err)
	return k
}

// testRootKeyVersion returns a new test RootKeyVersion with its associated wrapper
func testRootKeyVersion(t *testing.T, conn *dbw.DB, wrapper wrapping.Wrapper, rootId string) (kv *rootKeyVersion, kvWrapper wrapping.Wrapper) {
	t.Helper()
	require := require.New(t)
	testCtx := context.Background()
	rw := dbw.New(conn)
	rootKeyVersionWrapper := wrapping.NewTestWrapper([]byte(defaultWrapperSecret))
	key, err := rootKeyVersionWrapper.KeyBytes(testCtx)
	require.NoError(err)
	k, err := newRootKeyVersion(rootId, key)
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
func testDataKey(t *testing.T, conn *dbw.DB, rootKeyId string, purpose KeyPurpose) *dataKey {
	t.Helper()
	require := require.New(t)
	testDeleteWhere(t, conn, &dataKey{}, "root_key_id = ?", rootKeyId)
	rw := dbw.New(conn)
	k, err := newDataKey(rootKeyId, purpose)
	require.NoError(err)
	id, err := newDataKeyId()
	require.NoError(err)
	k.PrivateId = id
	k.RootKeyId = rootKeyId
	err = create(context.Background(), rw, k)
	require.NoError(err)
	return k
}

// testDataKeyVersion returns a new test DataKeyVersion with its associated wrapper
func testDataKeyVersion(t *testing.T, conn *dbw.DB, rootKeyVersionWrapper wrapping.Wrapper, dataKeyId string, key []byte) *dataKeyVersion {
	t.Helper()
	require := require.New(t)
	rw := dbw.New(conn)
	rootKeyVersionId, err := rootKeyVersionWrapper.KeyId(context.Background())
	require.NoError(err)
	require.NotEmpty(rootKeyVersionId)
	k, err := newDataKeyVersion(dataKeyId, key, rootKeyVersionId)
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

// testRepo returns are test repo
func testRepo(t *testing.T, db *dbw.DB, opt ...Option) *repository {
	t.Helper()
	require := require.New(t)
	rw := dbw.New(db)
	r, err := newRepository(rw, rw, opt...)
	require.NoError(err)
	return r
}

// TestDb will return a test db and a url for that db
func TestDb(t *testing.T) (*dbw.DB, string) {
	return dbw.TestSetup(t, dbw.WithTestMigrationUsingDB(testMigrationFn(t)))
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

// testDeleteWhere allows you to easily delete resources for testing purposes
// including all the current resources.
func testDeleteWhere(t *testing.T, conn *dbw.DB, i interface{}, whereClause string, args ...interface{}) {
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
