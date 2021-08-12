package aead

import (
	"encoding/base64"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) options {
	// First, separate out options into local and global
	opts := getDefaultOptions()
	var wrappingOptions []wrapping.Option
	var localOptions []Option
	for _, o := range opt {
		if o == nil {
			continue
		}
		switch to := o.(type) {
		case wrapping.OptionFunc:
			wrappingOptions = append(wrappingOptions, to)
		case Option:
			localOptions = append(localOptions, to)
		}
	}

	// Parse the global options
	opts.Options = wrapping.GetOpts(wrappingOptions...)
	// Don't ever return blank options
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	// Local options can be provided either via the WithWrapperOptions field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithWrapperOptions != nil {
		for k, v := range opts.WithWrapperOptions.GetFields() {
			switch k {
			case "aead_type":
				opts.WithAeadType = wrapping.AeadTypeMap(v.GetStringValue())
			case "hash_type":
				opts.WithHashType = wrapping.HashTypeMap(v.GetStringValue())
			case "key":
				opts.WithKey = v.GetStringValue()
			case "salt":
				opts.WithSalt, _ = base64.StdEncoding.DecodeString(v.GetStringValue())
			case "info":
				opts.WithInfo, _ = base64.StdEncoding.DecodeString(v.GetStringValue())
			}
		}
	}

	// Now run the local options functions. This may overwrite options set by
	// the options above.
	for _, o := range localOptions {
		if o != nil {
			o(&opts)
		}
	}

	return opts
}

// Option - a type for funcs that operate on the shared Options struct
type Option func(*options)

// options = how options are represented
type options struct {
	*wrapping.Options

	WithAeadType wrapping.AeadType
	WithHashType wrapping.HashType
	WithInfo     []byte
	WithKey      string
	WithSalt     []byte

	withLogger hclog.Logger
}

func getDefaultOptions() options {
	return options{
		WithAeadType: wrapping.AeadTypeAesGcm,
		WithHashType: wrapping.HashTypeSha256,
	}
}

// WithAeadType provides a way to chose the type of AEAD to use
func WithAeadType(aeadType wrapping.AeadType) Option {
	return func(o *options) {
		o.WithAeadType = aeadType
	}
}

// WithHashType provides a wat to choose the type of hash to use for derivation
func WithHashType(hash wrapping.HashType) Option {
	return func(o *options) {
		o.WithHashType = hash
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

// WithLogger provides a way to override default logger for some purposes (e.g.
// running as a plugin)
func WithLogger(logger hclog.Logger) Option {
	return func(o *options) {
		o.withLogger = logger
	}
}
