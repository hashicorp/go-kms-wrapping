// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package examples

import "embed"

// LocalSqliteFS contains the sql for creating additional sqlite tables for
// examples.
//
//go:embed sqlite-migrations
var LocalSqliteFS embed.FS
