package aead

import (
	"crypto/sha256"
	"hash"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...interface{}) options {
	opts := getDefaultOptions()
	var wrappingOpts []interface{}
	for _, o := range opt {
		if o != nil {
			switch t := o.(type) {
			case wrapping.Option:
				wrappingOpts = append(wrappingOpts, t)
			case Option:
				if t != nil {
					t(&opts)
				}
			}
		}
	}
	opts.Options = wrapping.GetOpts(wrappingOpts...)
	return opts
}

// Option - a type for funcs that operate on the shared Options struct
type Option func(*options)

// options = how options are represented
type options struct {
	wrapping.Options

	WithAeadType wrapping.AeadType
	WithHash     func() hash.Hash
	WithInfo     []byte
	WithKey      string
	WithSalt     []byte
}

func getDefaultOptions() options {
	return options{
		WithAeadType: wrapping.AeadTypeAesGcm,
		WithHash:     sha256.New,
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

// WithSalt provides optional salt for deriving wrappers
func WithSalt(salt []byte) Option {
	return func(o *options) {
		o.WithSalt = salt
	}
}
