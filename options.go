package wrapping

import (
	"github.com/hashicorp/go-hclog"
)

// GetOpts iterates the inbound Options and returns a struct
func GetOpts(opt ...interface{}) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			switch t := o.(type) {
			case Option:
				if t != nil {
					t(&opts)
				}
			}
		}
	}
	return opts
}

// Option - a type for funcs that operate on the shared Options struct
type Option func(*Options)

// Options contains values that are cross-wrapper. It is intended to be embedded
// in wrapper-specific options structs.
type Options struct {
	WithAad            []byte
	WithKeyId          string
	WithKeyNotRequired bool
	WithLogger         hclog.Logger
}

func getDefaultOptions() Options {
	return Options{}
}

// WithAad provides optional additional authenticated data
func WithAad(aad []byte) Option {
	return func(o *Options) {
		o.WithAad = aad
	}
}

// WithKeyId provides a common way to pass in a key identifier
func WithKeyId(id string) Option {
	return func(o *Options) {
		o.WithKeyId = id
	}
}

// WithKeyNotRequired is an option accepted by some wrappers indicating that a
// key isn't required when creating a wrapper, and will be provided later
func WithKeyNotRequired(notRequired bool) Option {
	return func(o *Options) {
		o.WithKeyNotRequired = notRequired
	}
}

// WithLogger provides an optional logger for logging any issues
func WithLogger(logger hclog.Logger) Option {
	return func(o *Options) {
		o.WithLogger = logger
	}
}
