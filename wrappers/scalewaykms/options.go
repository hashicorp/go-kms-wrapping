// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

import (
	"strconv"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
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

	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "disallow_env_vars":
				disallow, err := strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
				opts.withDisallowEnvVars = disallow
			case "key_not_required":
				keyNotRequired, err := strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
				opts.withKeyNotRequired = keyNotRequired
			case "key_id", "kms_key_id":
				opts.WithKeyId = v
			case "region":
				opts.withRegion = v
			case "project_id":
				opts.withProjectId = v
			case "access_key":
				opts.withAccessKey = v
			case "secret_key":
				opts.withSecretKey = v
			case "credentials_file":
				opts.withCredentialsFile = v
			case "profile":
				opts.withProfile = v
			case "api_url":
				opts.withAPIUrl = v
			}
		}
	}

	for _, o := range localOptions {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, err
			}
		}
	}

	if err := wrapping.ParsePaths(&opts.withCredentialsFile, &opts.withAccessKey, &opts.withSecretKey); err != nil {
		return nil, err
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

type options struct {
	*wrapping.Options

	withDisallowEnvVars bool
	withKeyNotRequired  bool
	withRegion          string
	withProjectId       string
	withAccessKey       string
	withSecretKey       string
	withCredentialsFile string
	withProfile         string
	withAPIUrl          string
}

func getDefaultOptions() options {
	return options{}
}

// WithDisallowEnvVars disables reading configuration from environment variables.
func WithDisallowEnvVars(with bool) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withDisallowEnvVars = with
			return nil
		})
	}
}

// WithKeyNotRequired allows SetConfig without a key ID (e.g. during seal migration).
func WithKeyNotRequired(with bool) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyNotRequired = with
			return nil
		})
	}
}
