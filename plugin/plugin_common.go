// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0
//go:build !js

package plugin

import "syscall"

const sighup = syscall.SIGHUP
