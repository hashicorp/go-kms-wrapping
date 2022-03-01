package yandexcloudkms

import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

const (
	// Accepted config parameters
	CfgYandexCloudOAuthToken            = "oauth_token"
	CfgYandexCloudServiceAccountKeyFile = "service_account_key_file"
	CfgYandexCloudKmsKeyId              = "kms_key_id"
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
			case CfgYandexCloudKmsKeyId:
				opts.WithKeyId = v // Handle deprecated parameter
			case CfgYandexCloudOAuthToken:
				opts.withOAuthToken = v
			case CfgYandexCloudServiceAccountKeyFile:
				opts.withServiceAccountKeyFile = v
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

	withOAuthToken            string
	withServiceAccountKeyFile string
}

func getDefaultOptions() options {
	return options{}
}

// WithOAuthToken provides a way to choose the OAuth token
func WithOAuthToken(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withOAuthToken = with
			return nil
		})
	}
}

// WithServiceAccounKeyFile provides a way to chose the service account key file
func WithServiceAccountKeyFile(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withServiceAccountKeyFile = with
			return nil
		})
	}
}
