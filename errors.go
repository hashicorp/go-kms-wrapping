// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package wrapping

import (
	"errors"
)

// ErrInvalidParameter represents an invalid parameter error
var ErrInvalidParameter = errors.New("invalid parameter")

// ErrFunctionNotImplemented represents a function that hasn't been implemented
var ErrFunctionNotImplemented = errors.New("the wrapping plugin does not implement this function")
