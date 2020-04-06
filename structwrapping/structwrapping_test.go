package structwrapping

import (
	"testing"

	"gotest.tools/assert"
)

func TestErrorConditions(t *testing.T) {
	t.Run("basic values", func(t *testing.T) {
		t.Parallel()
		var err error
		// Zero
		err = WrapStruct(nil, nil)
		assert.Error(t, err, "input not valid")
		err = WrapStruct(nil, interface{}(nil))
		assert.Error(t, err, "input not valid")
		err = WrapStruct(nil, "foobar")
		assert.Error(t, err, "input not a pointer")
		err = WrapStruct(nil, new(int32))
		assert.Error(t, err, "input not a struct")

		type badTagStruct struct {
			field string `wrapping:"foobar"`
		}
		err = WrapStruct(nil, new(badTagStruct))
		assert.Error(t, err, "error in wrapping tag specification")

		type badTagPrefixStruct struct {
			field string `wrapping:"dr,foobar"`
		}
		err = WrapStruct(nil, new(badTagPrefixStruct))
		assert.Error(t, err, "unknown tag type for wrapping tag")

	})

	t.Run("plaintext values", func(t *testing.T) {
		t.Parallel()
		var err error
		type badPTTypeStruct struct {
			field string `wrapping:"pt,foobar"`
		}
		err = WrapStruct(nil, new(badPTTypeStruct))
		assert.Error(t, err, "plaintext value is not a slice")

		type badPTSliceTypeStruct struct {
			field []int `wrapping:"pt,foobar"`
		}
		err = WrapStruct(nil, new(badPTSliceTypeStruct))
		assert.Error(t, err, "plaintext value is not a byte slice")
	})

	t.Run("ciphertext values", func(t *testing.T) {
		t.Parallel()
		var err error
		type badCTTypeStruct struct {
			field string `wrapping:"ct,foobar"`
		}
		err = WrapStruct(nil, new(badCTTypeStruct))
		assert.Error(t, err, "ciphertext value is not a pointer")

		type badCTSliceTypeStruct struct {
			field *int `wrapping:"ct,foobar"`
		}
		err = WrapStruct(nil, new(badCTSliceTypeStruct))
		assert.Error(t, err, "ciphertext value is not the expected type")
	})
}
