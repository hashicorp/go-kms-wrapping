package wrapping

import structpb "google.golang.org/protobuf/types/known/structpb"

// GetOpts iterates the inbound Options and returns a struct
func GetOpts(opt ...interface{}) *Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		switch to := o.(type) {
		case []byte:
			// This is legacy from when AAD was not an option. Panic here so
			// that it can easily be caught in tests.
			panic("aad must be input via WithAad")
		case Option:
			to(opts)
		}
	}
	return opts
}

// Option - a type for funcs that operate on the shared Options struct
type Option func(*Options)

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
