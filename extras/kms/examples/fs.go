// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package examples

import "embed"

// LocalSqliteFS contains the sql for creating additional sqlite tables for
// examples.
//
//go:embed sqlite-migrations
var LocalSqliteFS embed.FS
