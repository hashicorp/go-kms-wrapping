// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package tencentcloudkms

import (
	"fmt"
	"strconv"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

const (
	// minRoleDurationSeconds is the shortest session duration TencentCloud STS
	// accepts when assuming a role.
	minRoleDurationSeconds = uint64(900) // 15 minutes
	// maxRoleDurationSeconds is the longest session duration TencentCloud STS
	// accepts when assuming a role. Roles with a shorter "max session duration"
	// configured in CAM will yield an error from the service.
	maxRoleDurationSeconds = uint64(43200) // 12 hours
)

// parseRoleDurationSeconds converts a textual duration (in seconds) into a
// uint64, validating it against the range accepted by TencentCloud STS.
func parseRoleDurationSeconds(v string) (uint64, error) {
	d, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid 'role_duration_seconds' value %q: %w", v, err)
	}
	if d != 0 && (d < minRoleDurationSeconds || d > maxRoleDurationSeconds) {
		return 0, fmt.Errorf("invalid 'role_duration_seconds' value %d: must be between %d and %d seconds",
			d, minRoleDurationSeconds, maxRoleDurationSeconds)
	}
	return d, nil
}

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
			case "kms_key_id": // Handle deprecated KMS-specific value
				opts.WithKeyId = v
			case "region":
				opts.withRegion = v
			case "access_key":
				opts.withAccessKey = v
			case "secret_key":
				opts.withSecretKey = v
			case "session_token":
				opts.withSessionToken = v
			case "role_arn":
				opts.withRoleArn = v
			case "role_session_name":
				opts.withRoleSessionName = v
			case "role_external_id":
				opts.withRoleExternalId = v
			case "role_duration_seconds":
				d, err := parseRoleDurationSeconds(v)
				if err != nil {
					return nil, err
				}
				opts.withRoleDurationSeconds = d
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

	if err := wrapping.ParsePaths(&opts.withSecretKey, &opts.withAccessKey, &opts.withSessionToken); err != nil {
		return nil, err
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	*wrapping.Options

	withRegion          string
	withAccessKey       string
	withSecretKey       string
	withSessionToken    string
	withRoleArn              string
	withRoleSessionName      string
	withRoleExternalId       string
	withRoleDurationSeconds  uint64
}

func getDefaultOptions() options {
	return options{
		withRegion: "ap-guangzhou",
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

// WithAccessKey provides a way to chose the access key
func WithAccessKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withAccessKey = with
			return nil
		})
	}
}

// WithSecretKey provides a way to chose the secret key
func WithSecretKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withSecretKey = with
			return nil
		})
	}
}

// WithSessionToken provides a way to chose the session token
func WithSessionToken(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withSessionToken = with
			return nil
		})
	}
}

// WithRoleArn provides a way to specify a CAM role to assume. When set, the
// wrapper calls STS AssumeRole with the base credentials (access_key/secret_key)
// and uses the returned temporary credentials to talk to KMS.
func WithRoleArn(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withRoleArn = with
			return nil
		})
	}
}

// WithRoleSessionName provides a way to choose the session name used when
// assuming a role.
func WithRoleSessionName(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withRoleSessionName = with
			return nil
		})
	}
}

// WithRoleExternalId provides a way to specify an external id (similar to the
// AWS external id / confused deputy protection) when assuming a role.
func WithRoleExternalId(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withRoleExternalId = with
			return nil
		})
	}
}

// WithRoleDurationSeconds provides a way to choose how long the temporary
// credentials obtained from STS AssumeRole remain valid, in seconds. Valid
// values are between 900 (15 minutes) and 43200 (12 hours); the effective
// upper bound is also limited by the role's configured max session duration.
// A value of 0 means "unset", in which case the TencentCloud default (7200
// seconds) is used.
func WithRoleDurationSeconds(with uint64) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			if with != 0 && (with < minRoleDurationSeconds || with > maxRoleDurationSeconds) {
				return fmt.Errorf("invalid role duration seconds %d: must be between %d and %d",
					with, minRoleDurationSeconds, maxRoleDurationSeconds)
			}
			o.withRoleDurationSeconds = with
			return nil
		})
	}
}
