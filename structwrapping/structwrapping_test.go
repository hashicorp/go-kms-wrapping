package structwrapping

import (
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestStructWrapping(t *testing.T) {
	wrapper := aead.NewWrapper(nil)
	_, err := wrapper.SetConfig(map[string]string{"aead_type": "aes-gcm", "key": "QmjueU/LMsZAO+rvSUMcpkBziCD5ON7BgxVqcZ6+TCI="})
	assert.Nil(t, err)

	t.Run("shared encryption/decryption tests", func(t *testing.T) {
		t.Parallel()
		t.Run("bad basic values", func(t *testing.T) {
			t.Parallel()
			var err error
			// Zero
			err = WrapStruct(nil, nil, nil, nil)
			assert.Error(t, err, "nil wrapper passed in")
			err = WrapStruct(nil, wrapper, nil, nil)
			assert.Error(t, err, "input not valid")
			err = WrapStruct(nil, wrapper, interface{}(nil), nil)
			assert.Error(t, err, "input not valid")
			err = WrapStruct(nil, wrapper, "foobar", nil)
			assert.Error(t, err, "input not a pointer")
			err = WrapStruct(nil, wrapper, new(int32), nil)
			assert.Error(t, err, "input not a struct")

			type badTagStruct struct {
				field string `wrapping:"foobar"`
			}
			err = WrapStruct(nil, wrapper, new(badTagStruct), nil)
			assert.Error(t, err, "error in wrapping tag specification")

			type badTagPrefixStruct struct {
				field string `wrapping:"dr,foobar"`
			}
			err = WrapStruct(nil, wrapper, new(badTagPrefixStruct), nil)
			assert.Error(t, err, "unknown tag type for wrapping tag")

		})

		t.Run("doubled values", func(t *testing.T) {
			t.Parallel()
			var err error
			type doubledPTIdentifierStruct struct {
				PT1 []byte `wrapping:"pt,foobar"`
				PT2 []byte `wrapping:"pt,foobar"`
			}
			err = WrapStruct(nil, wrapper, &doubledPTIdentifierStruct{PT1: []byte("foo"), PT2: []byte("bar")}, nil)
			assert.Error(t, err, "detected two pt wrapping tags with the same identifier")

			type doubledCTIdentifierStruct struct {
				CT1 *wrapping.EncryptedBlobInfo `wrapping:"ct,foobar"`
				CT2 *wrapping.EncryptedBlobInfo `wrapping:"ct,foobar"`
			}
			err = WrapStruct(nil, wrapper, &doubledCTIdentifierStruct{}, nil)
			assert.Error(t, err, "detected two ct wrapping tags with the same identifier")
		})

		t.Run("mismatched values", func(t *testing.T) {
			t.Parallel()
			var err error
			type mismatchedPTStruct struct {
				PT1 []byte                      `wrapping:"pt,foo"`
				CT1 *wrapping.EncryptedBlobInfo `wrapping:"ct,foo"`
				PT2 []byte                      `wrapping:"pt,bar"`
			}
			err = WrapStruct(nil, wrapper, &mismatchedPTStruct{PT1: []byte("foo"), PT2: []byte("bar")}, nil)
			assert.Error(t, err, "no ct wrapping tag found for identifier \"bar\"")

			type mismatchedCTStruct struct {
				PT1 []byte                      `wrapping:"pt,bar"`
				CT1 *wrapping.EncryptedBlobInfo `wrapping:"ct,bar"`
				CT2 *wrapping.EncryptedBlobInfo `wrapping:"ct,foo"`
			}
			err = WrapStruct(nil, wrapper, &mismatchedPTStruct{PT1: []byte("foo")}, nil)
			assert.Error(t, err, "no pt wrapping tag found for identifier \"foo\"")
		})
	})

	t.Run("bad encryption tests", func(t *testing.T) {
		t.Parallel()
		t.Run("bad plaintext values", func(t *testing.T) {
			t.Parallel()
			var err error
			type badPTTypeStruct struct {
				field string `wrapping:"pt,foobar"`
			}
			err = WrapStruct(nil, wrapper, new(badPTTypeStruct), nil)
			assert.Error(t, err, "plaintext value is not a slice")

			type badPTSliceTypeStruct struct {
				field []int `wrapping:"pt,foobar"`
			}
			err = WrapStruct(nil, wrapper, new(badPTSliceTypeStruct), nil)
			assert.Error(t, err, "plaintext value is not a byte slice")

			type nilPTSliceStruct struct {
				Field   []byte                      `wrapping:"pt,foobar"`
				CTField *wrapping.EncryptedBlobInfo `wrapping:"ct,foobar"`
			}
			err = WrapStruct(nil, wrapper, new(nilPTSliceStruct), nil)
			assert.Error(t, err, "plaintext byte slice is nil")
		})
	})

	t.Run("bad decryption tests", func(t *testing.T) {
		t.Parallel()
		t.Run("bad ciphertext values", func(t *testing.T) {
			t.Parallel()
			var err error
			type badCTTypeStruct struct {
				field string `wrapping:"ct,foobar"`
			}
			err = UnwrapStruct(nil, wrapper, new(badCTTypeStruct), nil)
			assert.Error(t, err, "ciphertext value is not a pointer")

			type badCTSliceTypeStruct struct {
				field *int `wrapping:"ct,foobar"`
			}
			err = UnwrapStruct(nil, wrapper, new(badCTSliceTypeStruct), nil)
			assert.Error(t, err, "ciphertext value is not the expected type")

			type nilCTStruct struct {
				Field   []byte                      `wrapping:"pt,foobar"`
				CTField *wrapping.EncryptedBlobInfo `wrapping:"ct,foobar"`
			}
			err = UnwrapStruct(nil, wrapper, new(nilCTStruct), nil)
			assert.Error(t, err, "ciphertext pointer is nil")
		})
	})

	t.Run("good values", func(t *testing.T) {
		t.Parallel()
		var err error
		type sutStruct struct {
			PT1 []byte                      `wrapping:"pt,foo"`
			PT2 string                      `wrapping:"pt,bar"`
			PT3 []byte                      `wrapping:"pt,zip"`
			CT1 *wrapping.EncryptedBlobInfo `wrapping:"ct,foo"`
			CT2 []byte                      `wrapping:"ct,bar"`
			CT3 string                      `wrapping:"ct,zip"`
		}
		sut := &sutStruct{PT1: []byte("foo"), PT2: "bar", PT3: []byte("zip")}
		err = WrapStruct(nil, wrapper, sut, nil)
		assert.Nil(t, err)
		assert.NotNil(t, sut.CT1)
		assert.NotNil(t, sut.CT2)
		assert.NotNil(t, sut.CT3)

		fooVal, err := wrapper.Decrypt(nil, sut.CT1, nil)
		assert.Nil(t, err)
		assert.Equal(t, fooVal, []byte("foo"))

		ebi := new(wrapping.EncryptedBlobInfo)
		err = proto.Unmarshal(sut.CT2, ebi)
		assert.Nil(t, err)
		barVal, err := wrapper.Decrypt(nil, ebi, nil)
		assert.Nil(t, err)
		assert.Equal(t, barVal, []byte("bar"))

		ebi = new(wrapping.EncryptedBlobInfo)
		err = proto.Unmarshal([]byte(sut.CT3), ebi)
		assert.Nil(t, err)
		zipVal, err := wrapper.Decrypt(nil, ebi, nil)
		assert.Nil(t, err)
		assert.Equal(t, zipVal, []byte("zip"))

		sut2 := &sutStruct{CT1: sut.CT1, CT2: sut.CT2, CT3: sut.CT3}
		err = UnwrapStruct(nil, wrapper, sut2, nil)
		assert.Nil(t, err)
		assert.Equal(t, sut2.PT1, []byte("foo"))
		assert.Equal(t, sut2.PT2, "bar")
		assert.Equal(t, sut2.PT3, []byte("zip"))
	})
}
