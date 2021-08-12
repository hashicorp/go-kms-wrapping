package wrapping

import structpb "google.golang.org/protobuf/types/known/structpb"

// GetOpts iterates the inbound Options and returns a struct
func GetOpts(opt ...Option) *Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		switch to := o.(type) {
		case OptionFunc:
			to(opts)
		}
	}
	return opts
}

// Option - a type that wraps an interface for compile-time safety but can
// contain an option for this package or for wrappers implementing this
// interface
type Option interface{}

// OptionFunc - a type for funcs that operate on the shared Options struct
type OptionFunc func(*Options)

func getDefaultOptions() *Options {
	return &Options{}
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

// WithWrapperOptions is an option accepted by wrappers at configuration time
// and/or in other function calls to control wrapper-specific behavior.
func WithWrapperOptions(options *structpb.Struct) Option {
	return func(o *Options) {
		o.WithWrapperOptions = options
	}
}
