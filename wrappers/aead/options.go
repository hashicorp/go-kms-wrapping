package aead

import (
	"encoding/base64"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global
	opts := getDefaultOptions()
	var wrappingOptions []wrapping.Option
	var localOptions []OptionFunc
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case wrapping.OptionFunc:
			wrappingOptions = append(wrappingOptions, o)
		case OptionFunc:
			localOptions = append(localOptions, to)
		}
	}

	// Parse the global options
	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	// Don't ever return blank options
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	// Local options can be provided either via the WithWrapperOptions field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithWrapperOptions != nil {
		var err error
		for k, v := range opts.WithWrapperOptions.GetFields() {
			switch k {
			case "aead_type":
				opts.WithAeadType = wrapping.AeadTypeMap(v.GetStringValue())
			case "hash_type":
				opts.WithHashType = wrapping.HashTypeMap(v.GetStringValue())
			case "key":
				opts.WithKey, err = base64.StdEncoding.DecodeString(v.GetStringValue())
				if err != nil {
					return nil, fmt.Errorf("error base64-decoding key value: %w", err)
				}
			case "salt":
				opts.WithSalt, err = base64.StdEncoding.DecodeString(v.GetStringValue())
				if err != nil {
					return nil, fmt.Errorf("error base64-decoding salt value: %w", err)
				}
			case "info":
				opts.WithInfo, err = base64.StdEncoding.DecodeString(v.GetStringValue())
				if err != nil {
					return nil, fmt.Errorf("error base64-decoding info value: %w", err)
				}
			}
		}
	}

	// Now run the local options functions. This may overwrite options set by
	// the options above.
	for _, o := range localOptions {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, err
			}
		}
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	*wrapping.Options

	WithAeadType wrapping.AeadType
	WithHashType wrapping.HashType
	WithInfo     []byte
	WithKey      []byte
	WithSalt     []byte
}

func getDefaultOptions() options {
	return options{
		WithAeadType: wrapping.AeadTypeAesGcm,
		WithHashType: wrapping.HashTypeSha256,
	}
}

// WithAeadType provides a way to chose the type of AEAD to use
func WithAeadType(aeadType wrapping.AeadType) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.WithAeadType = aeadType
			return nil
		})
	}
}

// WithHashType provides a wat to choose the type of hash to use for derivation
func WithHashType(hash wrapping.HashType) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.WithHashType = hash
			return nil
		})
	}
}

// WithInfo provides optional info for deriving wrappers
func WithInfo(info []byte) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.WithInfo = info
			return nil
		})
	}
}

// WithKey provides a common way to pass in a key.
func WithKey(key []byte) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.WithKey = key
			return nil
		})
	}
}

// WithSalt provides optional salt for deriving wrappers
func WithSalt(salt []byte) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.WithSalt = salt
			return nil
		})
	}
}
