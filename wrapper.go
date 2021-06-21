package wrapping

import (
	"context"
)

type HmacSigner interface {
	// HmacKeyID is the ID of the key currently used for HMACing (if any)
	HmacKeyId() string
}

type InitFinalizer interface {
	// Init allows performing any necessary setup calls before using a
	// Wrapper.
	Init(context.Context) error

	// Finalize can be called when all usage of a Wrapper is done if any cleanup
	// or finalization is required.
	Finalize(context.Context) error
}

// Wrapper is an an interface where supporting implementations allow for
// encrypting and decrypting data.
type Wrapper interface {
	// Type is the type of Wrapper
	Type() WrapperType

	// KeyId is the ID of the key currently used for encryption
	KeyId() string

	// Encrypt encrypts the given byte slice and stores the resulting
	// information in the returned blob info. Which options are supported
	// depends on the underlying wrapper.
	Encrypt(context.Context, []byte, ...interface{}) (*BlobInfo, error)
	// Decrypt decrypts the given byte slice and stores the resulting
	// information in the returned byte slice. Which options are supported
	// depends on the underlying wrapper.
	Decrypt(context.Context, *BlobInfo, ...interface{}) ([]byte, error)
}
