// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

import (
	"errors"
	"fmt"
	"os"

	"github.com/scaleway/scaleway-sdk-go/scw"
)

func (w *Wrapper) authClientOptions() ([]scw.ClientOption, error) {
	switch {
	case w.credentialsFile != "" || w.profile != "":
		profile, err := w.loadAuthProfile()
		if err != nil {
			return nil, err
		}
		if profile.AccessKey == nil || *profile.AccessKey == "" {
			return nil, errors.New("scaleway credentials profile is missing access_key")
		}
		if profile.SecretKey == nil || *profile.SecretKey == "" {
			return nil, errors.New("scaleway credentials profile is missing secret_key")
		}
		return []scw.ClientOption{scw.WithProfile(profile)}, nil

	case w.accessKey != "" && w.secretKey != "":
		return []scw.ClientOption{scw.WithAuth(w.accessKey, w.secretKey)}, nil

	case !w.disallowEnvVars:
		if key := os.Getenv(EnvScalewayAccessKey); key != "" {
			if secret := os.Getenv(EnvScalewaySecretKey); secret != "" {
				return []scw.ClientOption{scw.WithAuth(key, secret)}, nil
			}
		}
		return []scw.ClientOption{scw.WithEnv()}, nil

	default:
		return nil, errors.New("scaleway credentials not configured: set credentials_file or profile in seal config, or provide access_key and secret_key")
	}
}

func (w *Wrapper) loadAuthProfile() (*scw.Profile, error) {
	if w.credentialsFile != "" {
		cfg, err := scw.LoadConfigFromPath(w.credentialsFile)
		if err != nil {
			return nil, fmt.Errorf("load scaleway credentials file %q: %w", w.credentialsFile, err)
		}
		if w.profile != "" {
			return cfg.GetProfile(w.profile)
		}
		return cfg.GetActiveProfile()
	}

	cfg, err := scw.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf(
			"load default scaleway config: %w (profile-only auth requires HOME or SCW_CONFIG_PATH; prefer credentials_file in production)",
			err,
		)
	}
	if w.profile != "" {
		return cfg.GetProfile(w.profile)
	}
	return cfg.GetActiveProfile()
}
