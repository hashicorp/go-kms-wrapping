package kms

import wrapping "github.com/hashicorp/go-kms-wrapping/v2"

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withLimit          int
	withRootWrapper    wrapping.Wrapper
	withRepository     *Repository
	withKeyId          string
	withOrderByVersion OrderBy
	withRetryCnt       uint
	withErrorsMatching func(error) bool
	withPurpose        KeyPurpose
}

var noOpErrorMatchingFn = func(error) bool { return false }

func getDefaultOptions() options {
	return options{
		withErrorsMatching: noOpErrorMatchingFn,
		withRetryCnt:       StdRetryCnt,
	}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are returned. If
// WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithRootWrapper sets the external root wrapper for a given scope
func WithRootWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withRootWrapper = w
	}
}

// WithRepository sets a repository for a given wrapper lookup, useful if in the
// middle of a transaction where the reader/writer need to be specified
func WithRepository(repo *Repository) Option {
	return func(o *options) {
		o.withRepository = repo
	}
}

// WithKeyId allows specifying a key ID that should be found in a scope's
// multiwrapper; if it is not found, keys will be refreshed
func WithKeyId(keyId string) Option {
	return func(o *options) {
		o.withKeyId = keyId
	}
}

// WithOrderByVersion provides an option to specify ordering by the
// CreateTime field.
func WithOrderByVersion(orderBy OrderBy) Option {
	return func(o *options) {
		o.withOrderByVersion = orderBy
	}
}

// WithRetryCount provides an optional specified retry count, otherwise the
// StdRetryCnt is used. You must specify WithRetryErrorsMatching if you want
// any retries at all.
func WithRetryCount(cnt uint) Option {
	return func(o *options) {
		o.withRetryCnt = cnt
	}
}

// WithRetryErrorsMatching provides an optional function to match transactions
// errors which should be retried.
func WithRetryErrorsMatching(matchingFn func(error) bool) Option {
	return func(o *options) {
		o.withErrorsMatching = matchingFn
	}
}

// WithPurpose provides an optional key purpose
func WithPurpose(purpose KeyPurpose) Option {
	return func(o *options) {
		o.withPurpose = purpose
	}
}
