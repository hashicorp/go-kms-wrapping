// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"strconv"
	"strings"

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
			case "kms_key_id": // deprecated backend-specific value, set global
				opts.WithKeyId = v
			case "endpoint":
				opts.withEndpoint = v
			case "ca_cert":
				opts.withCaCert = v
			case "client_cert":
				opts.withClientCert = v
			case "client_key":
				opts.withClientKey = v
			case "server_name":
				opts.withServerName = v
			case "timeout":
				var err error
				var timeout uint64
				timeout, err = strconv.ParseUint(v, 10, 64)
				if err != nil {
					return nil, err
				}
				opts.withTimeout = timeout
			case "encrypt_alg":
				opts.withCryptoParams = v
			case "tls12_ciphers":
				for _, cipher := range strings.Split(v, ",") {
					cipher = strings.TrimSpace(cipher)
					opts.withTls12Ciphers = append(opts.withTls12Ciphers, cipher)
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

	withEndpoint     string
	withCaCert       string
	withClientCert   string
	withClientKey    string
	withServerName   string
	withTimeout      uint64
	withCryptoParams string
	withTls12Ciphers []string
}

func getDefaultOptions() options {
	return options{
		withTimeout:      10,
		withCryptoParams: "AES_GCM",
	}
}

// WithEndpoint provides a way to chose the endpoint
func WithEndpoint(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withEndpoint = with
			return nil
		})
	}
}

// WithCaCert provides a way to chose the ca cert
func WithCaCert(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withCaCert = with
			return nil
		})
	}
}

// WithClientCert provides a way to chose the client cert
func WithClientCert(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withClientCert = with
			return nil
		})
	}
}

// WithClientKey provides a way to chose the client key
func WithClientKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withClientKey = with
			return nil
		})
	}
}

// WithServerName provides a way to chose the server name
func WithServerName(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withServerName = with
			return nil
		})
	}
}

// WithTimeout provides a way to chose the write timeout
func WithTimeout(with uint64) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withTimeout = with
			return nil
		})
	}
}

func WithCryptoParams(name string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withCryptoParams = name
			return nil
		})
	}
}

func WithTls12Ciphers(ciphers []string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withTls12Ciphers = ciphers
			return nil
		})
	}
}
