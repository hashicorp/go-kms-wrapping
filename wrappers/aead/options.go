package aead

import (
	"crypto/sha256"
	"hash"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// GetOpts iterates the inbound Options and returns a struct
func GetOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	WithAad      []byte
	WithAeadType wrapping.AeadType
	WithHash     func() hash.Hash
	WithInfo     []byte
	WithKey      string
	WithKeyId    string
	WithSalt     []byte
}

func getDefaultOptions() options {
	return options{
		WithAeadType: wrapping.AeadTypeAesGcm,
		WithHash:     sha256.New,
	}
}

// WithAad provides optional additional authenticated data
func WithAad(aad []byte) Option {
	return func(o *options) {
		o.WithAad = aad
	}
}

// WithAeadType provides a way to chose the type of AEAD to use
func WithAeadType(aeadType wrapping.AeadType) Option {
	return func(o *options) {
		o.WithAeadType = aeadType
	}
}

// WithHash provides a hash function to use for derivation
func WithHash(hash func() hash.Hash) Option {
	return func(o *options) {
		o.WithHash = hash
	}
}

// WithInfo provides optional info for deriving wrappers
func WithInfo(info []byte) Option {
	return func(o *options) {
		o.WithInfo = info
	}
}

// WithKey provides a common way to pass in a key. The key should be base64'd
// with standard encoding.
func WithKey(key string) Option {
	return func(o *options) {
		o.WithKey = key
	}
}

// WithKeyId provides a common way to pass in a key identifier
func WithKeyId(id string) Option {
	return func(o *options) {
		o.WithKeyId = id
	}
}

// WithSalt provides optional salt for deriving wrappers
func WithSalt(salt []byte) Option {
	return func(o *options) {
		o.WithSalt = salt
	}
}
