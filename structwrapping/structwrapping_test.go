package structwrapping

import (
	"context"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/wrappers/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestStructWrapping(t *testing.T) {
	wrapper := aead.NewWrapper()
	_, err := wrapper.SetConfig(
		wrapping.WithAeadType(wrapping.AeadTypeAesGcm),
		wrapping.WithKey("QmjueU/LMsZAO+rvSUMcpkBziCD5ON7BgxVqcZ6+TCI="),
	)
	require.Nil(t, err)
	ctx := context.Background()

	t.Run("shared encryption/decryption tests", func(t *testing.T) {
		t.Parallel()
		t.Run("bad basic values", func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			var err error
			// Zero
			err = WrapStruct(ctx, nil, nil)
			assert.Error(err, "nil wrapper passed in")
			err = WrapStruct(ctx, wrapper, nil)
			assert.Error(err, "input not valid")
			err = WrapStruct(ctx, wrapper, interface{}(nil))
			assert.Error(err, "input not valid")
			err = WrapStruct(ctx, wrapper, "foobar")
			assert.Error(err, "input not a pointer")
			err = WrapStruct(ctx, wrapper, new(int32))
			assert.Error(err, "input not a struct")

			type badTagStruct struct {
				field string `wrapping:"foobar"`
			}
			err = WrapStruct(ctx, wrapper, new(badTagStruct))
			assert.Error(err, "error in wrapping tag specification")

			type badTagPrefixStruct struct {
				field string `wrapping:"dr,foobar"`
			}
			err = WrapStruct(ctx, wrapper, new(badTagPrefixStruct))
			assert.Error(err, "unknown tag type for wrapping tag")
		})

		t.Run("doubled values", func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			var err error
			type doubledPTIdentifierStruct struct {
				PT1 []byte `wrapping:"pt,foobar"`
				PT2 []byte `wrapping:"pt,foobar"`
			}
			err = WrapStruct(ctx, wrapper, &doubledPTIdentifierStruct{PT1: []byte("foo"), PT2: []byte("bar")}, nil)
			assert.Error(err, "detected two pt wrapping tags with the same identifier")

			type doubledCTIdentifierStruct struct {
				CT1 *wrapping.BlobInfo `wrapping:"ct,foobar"`
				CT2 *wrapping.BlobInfo `wrapping:"ct,foobar"`
			}
			err = WrapStruct(ctx, wrapper, &doubledCTIdentifierStruct{})
			assert.Error(err, "detected two ct wrapping tags with the same identifier")
		})

		t.Run("mismatched values", func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			var err error
			type mismatchedPTStruct struct {
				PT1 []byte             `wrapping:"pt,foo"`
				CT1 *wrapping.BlobInfo `wrapping:"ct,foo"`
				PT2 []byte             `wrapping:"pt,bar"`
			}
			err = WrapStruct(ctx, wrapper, &mismatchedPTStruct{PT1: []byte("foo"), PT2: []byte("bar")}, nil)
			assert.Error(err, "no ct wrapping tag found for identifier \"bar\"")

			type mismatchedCTStruct struct {
				PT1 []byte             `wrapping:"pt,bar"`
				CT1 *wrapping.BlobInfo `wrapping:"ct,bar"`
				CT2 *wrapping.BlobInfo `wrapping:"ct,foo"`
			}
			err = WrapStruct(ctx, wrapper, &mismatchedPTStruct{PT1: []byte("foo")})
			assert.Error(err, "no pt wrapping tag found for identifier \"foo\"")
		})
	})

	t.Run("bad encryption tests", func(t *testing.T) {
		t.Parallel()
		t.Run("bad plaintext values", func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			var err error
			type badPTTypeStruct struct {
				field string `wrapping:"pt,foobar"`
			}
			err = WrapStruct(ctx, wrapper, new(badPTTypeStruct))
			assert.Error(err, "plaintext value is not a slice")

			type badPTSliceTypeStruct struct {
				field []int `wrapping:"pt,foobar"`
			}
			err = WrapStruct(ctx, wrapper, new(badPTSliceTypeStruct))
			assert.Error(err, "plaintext value is not a byte slice")

			type nilPTSliceStruct struct {
				Field   []byte             `wrapping:"pt,foobar"`
				CTField *wrapping.BlobInfo `wrapping:"ct,foobar"`
			}
			err = WrapStruct(ctx, wrapper, new(nilPTSliceStruct))
			assert.Error(err, "plaintext byte slice is nil")
		})
	})

	t.Run("bad decryption tests", func(t *testing.T) {
		t.Parallel()
		t.Run("bad ciphertext values", func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			var err error
			type badCTTypeStruct struct {
				field string `wrapping:"ct,foobar"`
			}
			err = UnwrapStruct(ctx, wrapper, new(badCTTypeStruct))
			assert.Error(err, "ciphertext value is not a pointer")

			type badCTSliceTypeStruct struct {
				field *int `wrapping:"ct,foobar"`
			}
			err = UnwrapStruct(ctx, wrapper, new(badCTSliceTypeStruct))
			assert.Error(err, "ciphertext value is not the expected type")

			type nilCTStruct struct {
				Field   []byte             `wrapping:"pt,foobar"`
				CTField *wrapping.BlobInfo `wrapping:"ct,foobar"`
			}
			err = UnwrapStruct(ctx, wrapper, new(nilCTStruct))
			assert.Error(err, "ciphertext pointer is nil")
		})
	})

	t.Run("good values", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		var err error
		type sutStruct struct {
			PT1 []byte             `wrapping:"pt,foo"`
			PT2 string             `wrapping:"pt,bar"`
			PT3 []byte             `wrapping:"pt,zip"`
			CT1 *wrapping.BlobInfo `wrapping:"ct,foo"`
			CT2 []byte             `wrapping:"ct,bar"`
			CT3 string             `wrapping:"ct,zip"`
		}
		sut := &sutStruct{PT1: []byte("foo"), PT2: "bar", PT3: []byte("zip")}
		err = WrapStruct(ctx, wrapper, sut)
		assert.Nil(err)
		assert.NotNil(sut.CT1)
		assert.NotNil(sut.CT2)
		assert.NotNil(sut.CT3)

		fooVal, err := wrapper.Decrypt(ctx, sut.CT1)
		assert.Nil(err)
		assert.Equal(fooVal, []byte("foo"))

		ebi := new(wrapping.BlobInfo)
		err = proto.Unmarshal(sut.CT2, ebi)
		assert.Nil(err)
		barVal, err := wrapper.Decrypt(ctx, ebi)
		assert.Nil(err)
		assert.Equal(barVal, []byte("bar"))

		ebi = new(wrapping.BlobInfo)
		err = proto.Unmarshal([]byte(sut.CT3), ebi)
		assert.Nil(err)
		zipVal, err := wrapper.Decrypt(ctx, ebi)
		assert.Nil(err)
		assert.Equal(zipVal, []byte("zip"))

		sut2 := &sutStruct{CT1: sut.CT1, CT2: sut.CT2, CT3: sut.CT3}
		err = UnwrapStruct(ctx, wrapper, sut2)
		assert.Nil(err)
		assert.Equal(sut2.PT1, []byte("foo"))
		assert.Equal(sut2.PT2, "bar")
		assert.Equal(sut2.PT3, []byte("zip"))
	})
}
