package wrapping

import (
	"errors"

	structpb "google.golang.org/protobuf/types/known/structpb"
)

// GetOpts iterates the inbound Options and returns a struct
func GetOpts(opt ...Option) (*Options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case OptionFunc:
			to(opts)
		default:
			return nil, errors.New("Option passed into top-level wrapping options handler" +
				" that is not from this package; options from specific wrappers must be passed" +
				" to functions directly on that wrapper. This is likely due to the wrapper being" +
				" invoked as a plugin but options being sent from a specific wrapper package." +
				" Use WithWrapperOptions to send options via the plugin interface.")
		}
	}
	return opts, nil
}

// Option - a type that wraps an interface for compile-time safety but can
// contain an option for this package or for wrappers implementing this
// interface.
type Option func() interface{}

// OptionFunc - a type for funcs that operate on the shared Options struct. The
// options below explicitly wrap this so that we can switch on it when parsing
// opts for various wrappers.
type OptionFunc func(*Options)

func getDefaultOptions() *Options {
	return &Options{}
}

// WithAad provides optional additional authenticated data
func WithAad(aad []byte) Option {
	return func() interface{} {
		return OptionFunc(func(o *Options) {
			o.WithAad = aad
		})
	}
}

// WithKeyId provides a common way to pass in a key identifier
func WithKeyId(id string) Option {
	return func() interface{} {
		return OptionFunc(func(o *Options) {
			o.WithKeyId = id
		})
	}
}

// WithWrapperOptions is an option accepted by wrappers at configuration time
// and/or in other function calls to control wrapper-specific behavior.
func WithWrapperOptions(options *structpb.Struct) Option {
	return func() interface{} {
		return OptionFunc(func(o *Options) {
			o.WithWrapperOptions = options
		})
	}
}
