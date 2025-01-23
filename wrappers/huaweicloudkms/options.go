// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package huaweicloudkms

import (
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

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "kms_key_id": // Handle deprecated parameter
				opts.WithKeyId = v
			case "region":
				opts.withRegion = v
			case "project":
				opts.withProject = v
			case "access_key":
				opts.withAccessKey = v
			case "secret_key":
				opts.withSecretKey = v
			case "identity_endpoint":
				opts.withIdentityEndpoint = v
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

	if err := wrapping.ParsePaths(&opts.withSecretKey, &opts.withAccessKey); err != nil {
		return nil, err
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	*wrapping.Options

	withRegion           string
	withProject          string
	withAccessKey        string
	withSecretKey        string
	withIdentityEndpoint string
}

func getDefaultOptions() options {
	return options{
		withIdentityEndpoint: "https://iam.myhwclouds.com:443/v3",
	}
}

// WithRegion provides a way to chose the region
func WithRegion(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withRegion = with
			return nil
		})
	}
}

// WithProject provides a way to chose the project
func WithProject(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withProject = with
			return nil
		})
	}
}

// WithAccessKey provides a way to specify an access key
func WithAccessKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withAccessKey = with
			return nil
		})
	}
}

// WithSecretKey provides a way to specify a secret key
func WithSecretKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withSecretKey = with
			return nil
		})
	}
}

// WithIdentityEndpoint provides a way to choose an identity endpoint
func WithIdentityEndpoint(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withIdentityEndpoint = with
			return nil
		})
	}
}
