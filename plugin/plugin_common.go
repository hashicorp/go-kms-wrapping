// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: MPL-2.0
//go:build !js

package plugin

import "syscall"

const sighup = syscall.SIGHUP
