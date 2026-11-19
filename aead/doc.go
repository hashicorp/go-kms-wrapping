// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

// Package aead provides an AES-GCM wrapping implementation.
//
// Build with the gofips tag to use native Go FIPS AES-GCM, which generates
// nonces internally. In that build, callers cannot supply an IV or random
// reader.
package aead
