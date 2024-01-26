// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azurekeyvault

import (
	"strconv"

	"github.com/hashicorp/go-hclog"
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
			case "disallow_env_vars":
				disallowEnvVars, err := strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
				opts.withDisallowEnvVars = disallowEnvVars
			case "key_not_required":
				keyNotRequired, err := strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
				opts.withKeyNotRequired = keyNotRequired
			case "tenant_id":
				opts.withTenantId = v
			case "client_id":
				opts.withClientId = v
			case "client_secret":
				opts.withClientSecret = v
			case "environment":
				opts.withEnvironment = v
			case "resource":
				opts.withResource = v
			case "vault_name":
				opts.withVaultName = v
			case "key_name":
				opts.withKeyName = v
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

	withDisallowEnvVars bool
	withKeyNotRequired  bool
	withTenantId        string
	withClientId        string
	withClientSecret    string
	withEnvironment     string
	withResource        string
	withVaultName       string
	withKeyName         string

	withLogger hclog.Logger
}

func getDefaultOptions() options {
	return options{}
}
