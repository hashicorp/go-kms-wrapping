package examples

import "embed"

// LocalSqliteFS contains the sql for creating additional sqlite tables for
// examples.
//go:embed sqlite-migrations
var LocalSqliteFS embed.FS
