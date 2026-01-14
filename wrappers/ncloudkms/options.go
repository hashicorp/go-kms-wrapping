package ncloudkms

import (
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

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
		for k, _ := range opts.WithConfigMap {
			switch k {
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

	return &opts, nil
}

type OptionFunc func(*options) error

type options struct {
	*wrapping.Options

	withLogger hclog.Logger
}

func getDefaultOptions() options {
	return options{}
}
