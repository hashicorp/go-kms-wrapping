package plugin

import (
	"errors"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...Option) (*options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case OptionFunc:
			to(opts)
		default:
			return nil, errors.New("option passed in that does not belong to this package")
		}
	}
	return opts, nil
}

type options struct {
	withLogger        hclog.Logger
	withInitFinalizer wrapping.InitFinalizer
	withHmacComputer  wrapping.HmacComputer
}

// Option - a type that wraps an interface for compile-time safety but can
// contain an option for this package or for wrappers implementing this
// interface.
type Option func() interface{}

// OptionFunc - a type for funcs that operate on the shared Options struct. The
// options below explicitly wrap this so that we can switch on it when parsing
// opts for various wrappers.
type OptionFunc func(*options)

func getDefaultOptions() *options {
	return &options{}
}

// WithInitFinalizerInterface controls whether the client should expose
// wrapping.InitFinalizer
func WithInitFinalizerInterface(with wrapping.InitFinalizer) Option {
	return func() interface{} {
		return OptionFunc(func(o *options) {
			o.withInitFinalizer = with
		})
	}
}

// WithHmacComputerInterface controls whether the client should expose
// wrapping.HmacComputer
func WithHmacComputerInterface(with wrapping.HmacComputer) Option {
	return func() interface{} {
		return OptionFunc(func(o *options) {
			o.withHmacComputer = with
		})
	}
}

// WithLogger allows passing a logger to the plugin library for debugging
func WithLogger(with hclog.Logger) Option {
	return func() interface{} {
		return OptionFunc(func(o *options) {
			o.withLogger = with
		})
	}
}
