package wrapping

import (
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
	WithKeyNotRequired bool
	WithLogger         hclog.Logger
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
