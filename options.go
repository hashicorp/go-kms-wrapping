package wrapping

import (
	"hash"

	"github.com/hashicorp/go-hclog"
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
	WithAad            []byte
	WithAeadType       AeadType
	WithHash           func() hash.Hash
	WithInfo           []byte
	WithKey            string
	WithKeyId          string
	WithKeyNotRequired bool
	WithLogger         hclog.Logger
	WithSalt           []byte
}

func getDefaultOptions() options {
	return options{}
}

// WithAad provides optional additional authenticated data
func WithAad(aad []byte) Option {
	return func(o *options) {
		o.WithAad = aad
	}
}

// WithAeadType provides a way to chose the type of AEAD to use
func WithAeadType(aeadType AeadType) Option {
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

// WithKeyNotRequired is an option accepted by some wrappers indicating that a
// key isn't required when creating a wrapper, and will be provided later
func WithKeyNotRequired(notRequired bool) Option {
	return func(o *options) {
		o.WithKeyNotRequired = notRequired
	}
}

// WithLogger provides an optional logger for logging any issues
func WithLogger(logger hclog.Logger) Option {
	return func(o *options) {
		o.WithLogger = logger
	}
}

// WithSalt provides optional salt for deriving wrappers
func WithSalt(salt []byte) Option {
	return func(o *options) {
		o.WithSalt = salt
	}
}
