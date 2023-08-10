// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import reflect "reflect"

func isNil(i interface{}) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}
