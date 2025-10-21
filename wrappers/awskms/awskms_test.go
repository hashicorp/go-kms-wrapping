// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awskms

import (
	"context"
	"os"
	"reflect"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	awsTestKeyId  = "foo"
	envAwsProfile = "AWS_PROFILE"
	envAwsRegion  = "AWS_REGION"
)

func TestAwsKmsWrapper(t *testing.T) {
	// Test with empty key, expect error
	oldKeyId := os.Getenv(EnvAwsKmsWrapperKeyId)
	os.Setenv(EnvAwsKmsWrapperKeyId, "")
	defer os.Setenv(EnvAwsKmsWrapperKeyId, oldKeyId)

	s := NewWrapper()
	s.client = &mockClient{
		keyId: awsTestKeyId,
	}

	_, err := s.SetConfig(t.Context())
	if err == nil {
		t.Fatal("expected error when AwsKms wrapping key ID is not provided")
	}

	// Test with set key, expect no error
	os.Setenv(EnvAwsKmsWrapperKeyId, oldKeyId)

	_, err = s.SetConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
}

func TestAwsKmsWrapper_IgnoreEnv(t *testing.T) {
	wrapper := NewAwsKmsTestWrapper()

	// Setup environment values to ignore for the following values
	for _, envVar := range []string{EnvAwsKmsWrapperKeyId, EnvVaultAwsKmsSealKeyId, EnvAwsKmsEndpoint, DeprecatedEnvAwsKmsEndpoint} {
		oldVal := os.Getenv(envVar)
		os.Setenv(envVar, "envValue")
		defer os.Setenv(envVar, oldVal)
	}

	config := map[string]string{
		"disallow_env_vars": "true",
		"kms_key_id":        "a-key-key",
		"access_key":        "a-access-key",
		"secret_key":        "a-secret-key",
		"endpoint":          "my-endpoint",
	}

	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(config))
	assert.NoError(t, err)

	require.Equal(t, config["access_key"], wrapper.accessKey)
	require.Equal(t, config["secret_key"], wrapper.secretKey)
	require.Equal(t, config["kms_key_id"], wrapper.keyId)
	require.Equal(t, config["endpoint"], wrapper.endpoint)
}

func TestAwsKmsWrapper_Lifecycle(t *testing.T) {
	if os.Getenv(EnvAwsKmsWrapperKeyId) == "" && os.Getenv(EnvVaultAwsKmsSealKeyId) == "" {
		t.SkipNow()
	}
	s := NewAwsKmsTestWrapper()
	oldKeyId := os.Getenv(EnvAwsKmsWrapperKeyId)
	os.Setenv(EnvAwsKmsWrapperKeyId, awsTestKeyId)
	defer os.Setenv(EnvAwsKmsWrapperKeyId, oldKeyId)
	testEncryptionRoundTrip(t, s)
}

// This test executes real calls. The calls themselves should be free,
// but the KMS key used is generally not free. AWS charges about $1/month
// per key.
//
// To run this test, the following env variables need to be set:
//   - AWSKMS_WRAPPER_KEY_ID or VAULT_AWSKMS_SEAL_KEY_ID
//   - AWS_REGION
//   - AWS_ACCESS_KEY_ID
//   - AWS_SECRET_ACCESS_KEY
func TestAccAwsKmsWrapper_Lifecycle(t *testing.T) {
	if os.Getenv(EnvAwsKmsWrapperKeyId) == "" && os.Getenv(EnvVaultAwsKmsSealKeyId) == "" {
		t.SkipNow()
	}
	s := NewWrapper()
	testEncryptionRoundTrip(t, s)
}

func testEncryptionRoundTrip(t *testing.T, w *Wrapper) {
	w.SetConfig(context.Background())
	input := []byte("foo")
	swi, err := w.Encrypt(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := w.Decrypt(context.Background(), swi, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}

func TestAwsKmsWrapper_custom_endpoint(t *testing.T) {
	customEndpoint := "https://custom.endpoint"
	customEndpoint2 := "https://custom.endpoint.2"

	// unset at end of test
	os.Setenv(EnvAwsKmsWrapperKeyId, awsTestKeyId)
	defer func() {
		if err := os.Unsetenv(EnvAwsKmsWrapperKeyId); err != nil {
			t.Fatal(err)
		}
	}()

	cfg := make(map[string]string)
	cfg["endpoint"] = customEndpoint

	testCases := []struct {
		Title    string
		Env      string
		Config   map[string]string
		Expected string
	}{
		{
			// Default will have nil for the config endpoint, and be looked up
			// dynamically by the SDK
			Title: "Default",
		},
		{
			Title:    "Environment",
			Env:      customEndpoint,
			Expected: customEndpoint,
		},
		{
			Title:    "Config",
			Config:   cfg,
			Expected: customEndpoint,
		},
		{
			// Expect environment to take precedence over configuration
			Title:    "Env-Config",
			Env:      customEndpoint2,
			Config:   cfg,
			Expected: customEndpoint2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Title, func(t *testing.T) {
			s := NewAwsKmsTestWrapper()

			if tc.Env != "" {
				if err := os.Setenv(EnvAwsKmsEndpoint, tc.Env); err != nil {
					t.Fatal(err)
				}
			}

			// cfg starts as nil, and takes a test case value if given. If not,
			// SetConfig is called with nil and creates it's own config
			var cfg map[string]string
			if tc.Config != nil {
				cfg = tc.Config
			}
			if _, err := s.SetConfig(context.Background(), wrapping.WithConfigMap(cfg)); err != nil {
				t.Fatalf("error setting config: %s", err)
			}

			// call GetAwsKmsClient() to get the configured client and verify its
			// endpoint
			k, err := s.GetAwsKmsClient(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			actualEndpoint := k.Options().BaseEndpoint
			if tc.Expected == "" && actualEndpoint != nil {
				t.Fatalf("Expected nil endpoint, got: (%s)", *actualEndpoint)
			}

			if tc.Expected != "" {
				if *actualEndpoint == "" {
					t.Fatal("expected custom endpoint, but config was nil")
				}
				if *actualEndpoint != tc.Expected {
					t.Fatalf("expected custom endpoint (%s), got: (%s)", tc.Expected, *actualEndpoint)
				}
			}

			// clear endpoint env after each test
			if err := os.Unsetenv(EnvAwsKmsEndpoint); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedProfiles(t *testing.T) {
	if os.Getenv(envAwsRegion) == "" {
		t.Skip("AWS_REGION required for shared profiles tests")
	}
	if os.Getenv(EnvAwsKmsWrapperKeyId) == "" && os.Getenv(EnvVaultAwsKmsSealKeyId) == "" {
		t.Skip("AWSKMS_WRAPPER_KEY_ID or VAULT_AWSKMS_SEAL_KEY_ID required for shared profiles tests")
	}
	// Test fail when shared profile doesn't exist
	old := ""
	if old = os.Getenv(envAwsProfile); old != "" {
		os.Setenv(envAwsProfile, "")
	}

	w := NewWrapper()

	_, err := w.SetConfig(t.Context(), WithSharedCredsProfile("this-profile-definitely-doesn't-exist"))
	require.Error(t, err)

	// Test shared profile from WithSharedCredsProfile
	// Shared profile test setup:
	// - Create a role in AWS that whatever role/user you're authenticating as has permission to sts::SetSourceIdentity as
	// - Create two profiles in ~/.aws/config
	//   - A source profile that has credentials or some method of logging in
	//   - A sink profile that uses `source_profile=$YOUR_SOURCE_PROFILE` and `role_arn=$YOUR_NEW_ROLE`
	//
	// - Set AWS_PROFILE=$SINK_PROFILE (for shared profile through AWS_PROFILE)
	// - Set TEST_PROFILE=$SINK_PROFILE (for shared profile through WithSharedCredsProfile)
	// - Set AWS_REGION and AWS_KMS_WRAPPER_KEY_ID as above
	prof := os.Getenv("TEST_PROFILE")
	if prof == "" {
		t.Skip("TEST_PROFILE required for shared profile from WithSharedCredsProfile test")
	}

	w = NewWrapper()

	_, err = w.SetConfig(t.Context(), WithSharedCredsProfile(prof))
	require.NoError(t, err)

	testEncryptionRoundTrip(t, w)

	os.Setenv(envAwsProfile, old)

	// Test shared profile from env
	// Default awskms config pulls shared creds from AWS_PROFILE if it's set
	if os.Getenv(envAwsProfile) == "" {
		t.Skip("AWS_PROFILE required for shared profile from AWS_PROFILE test")
	}

	w = NewWrapper()
	_, err = w.SetConfig(t.Context())
	require.NoError(t, err)
	testEncryptionRoundTrip(t, w)
}

func NewAwsKmsTestWrapper() *Wrapper {
	s := NewWrapper()
	s.client = &mockClient{
		keyId: awsTestKeyId,
	}
	return s
}
