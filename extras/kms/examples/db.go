// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package examples

import (
	"context"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/golang-migrate/migrate/v4"
	sqliteMigrator "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/httpfs"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	"gorm.io/driver/sqlite"
)

// OpenDB returns an open db connection with it's migrations already run
func OpenDB(ctx context.Context, debug bool) (*dbw.RW, error) {
	const (
		dialect          = "sqlite"
		inMemorySqlite   = "file::memory:?cache=shared"
		cliMigrationsDir = "sqlite-migrations"
		tempDirPrefix    = "migration-"
	)

	dialector := sqlite.Open(inMemorySqlite)
	var dbOpts []dbw.Option
	if !debug {
		dbOpts = append(dbOpts, dbw.WithLogger(hclog.NewNullLogger()))
	}
	db, err := dbw.OpenWith(dialector, dbOpts...)
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.SqlDB(ctx)
	if err != nil {
		return nil, err
	}
	driver, err := sqliteMigrator.WithInstance(sqlDB, &sqliteMigrator.Config{})
	if err != nil {
		return nil, err
	}

	dir, err := ioutil.TempDir(".", tempDirPrefix)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	baseMigrations, _ := fs.ReadDir(migrations.SqliteFS, dialect)
	for _, m := range baseMigrations {
		sql, err := fs.ReadFile(migrations.SqliteFS, fmt.Sprintf("%s/%s", dialect, m.Name()))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(fmt.Sprintf("%s/%s", dir, m.Name()), sql, 0o666); err != nil {
			return nil, err
		}
	}
	cliMigrations, _ := fs.ReadDir(LocalSqliteFS, cliMigrationsDir)
	for _, m := range cliMigrations {
		sql, err := fs.ReadFile(LocalSqliteFS, fmt.Sprintf("%s/%s", cliMigrationsDir, m.Name()))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(fmt.Sprintf("%s/%s", dir, m.Name()), sql, 0o666); err != nil {
			return nil, err
		}
	}

	source, err := httpfs.New(http.Dir("."), dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open migrations: %w", err)
	}
	m, err := migrate.NewWithInstance(
		dialect,
		source,
		dialect,
		driver)
	if err != nil {
		return nil, err
	}
	err = m.Up()
	if err != nil {
		return nil, err
	}
	rw := dbw.New(db)
	if debug {
		rw.DB().Debug(true)
	}
	return rw, nil
}
