// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package static

import (
	"github.com/hashicorp/go-hclog"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
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

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "previous_key":
				opts.withPreviousKey = v
			case "previous_key_id":
				opts.withPreviousKeyId = v
			case "current_key":
				opts.withCurrentKey = v
			case "current_key_id":
				opts.withCurrentKeyId = v
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

	if err := wrapping.ParsePaths(&opts.withPreviousKey, &opts.withCurrentKey); err != nil {
		return nil, err
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	*wrapping.Options

	withPreviousKey   string
	withPreviousKeyId string
	withCurrentKey    string
	withCurrentKeyId  string

	withLogger hclog.Logger
}

func getDefaultOptions() options {
	return options{}
}

// WithPreviousKey provides a way to choose the previous encryption key
func WithPreviousKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPreviousKey = with
			return nil
		})
	}
}

// WithPreviousKeyId provides a way to choose the id of the previous encryption key
func WithPreviousKeyId(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPreviousKeyId = with
			return nil
		})
	}
}

// WithCurrentKey provides a way to choose the current encryption key
func WithCurrentKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withCurrentKey = with
			return nil
		})
	}
}

// WithCurrentKey provides a way to choose the id of the current encryption key
func WithCurrentKeyId(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withCurrentKeyId = with
			return nil
		})
	}
}
