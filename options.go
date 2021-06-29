package wrapping

// GetOpts iterates the inbound Options and returns a struct
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
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
	WithWrapperOptions map[string]string
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

// WithWrapperOptions is an option accepted by wrappers at configuration time
// and/or in other function calls to control wrapper-specific behavior.
func WithWrapperOptions(options map[string]string) Option {
	return func(o *Options) {
		o.WithWrapperOptions = options
	}
}
