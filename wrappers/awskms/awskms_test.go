// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awskms

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	awsTestKeyId  = "foo"
	envAwsProfile = "AWS_PROFILE"
	envAwsRegion  = "AWS_REGION"
)

func TestSetConfig(t *testing.T) {
	// Works around lack of AWS_REGION var in CI
	if os.Getenv(envAwsRegion) == "" {
		os.Setenv(envAwsRegion, "us-west-2")
		defer os.Setenv(envAwsRegion, "")
	}

	t.Run("Failure - No wrapper key ID", func(t *testing.T) {
		wrapperWithMock := NewWrapper()
		wrapperWithMock.client = &mockClient{
			keyId: awsTestKeyId,
		}
		oldKeyId := os.Getenv(EnvAwsKmsWrapperKeyId)
		os.Setenv(EnvAwsKmsWrapperKeyId, "")
		defer os.Setenv(EnvAwsKmsWrapperKeyId, oldKeyId)

		_, err := wrapperWithMock.SetConfig(context.Background())
		require.Error(t, err, "expected error when AwsKms wrapping key ID is not provided")
	})

	t.Run("Success - Test key ID pulled from environment variables", func(t *testing.T) {
		wrapperWithMock := NewWrapper()
		wrapperWithMock.client = &mockClient{
			keyId: awsTestKeyId,
		}
		oldKeyId := os.Getenv(EnvAwsKmsWrapperKeyId)
		os.Setenv(EnvAwsKmsWrapperKeyId, awsTestKeyId)
		defer os.Setenv(EnvAwsKmsWrapperKeyId, oldKeyId)

		_, err := wrapperWithMock.SetConfig(context.Background())
		require.NoError(t, err)
	})

	t.Run("Success - Ignore environment variables", func(t *testing.T) {
		// Setup environment values to ignore for the following values
		for _, envVar := range []string{EnvAwsKmsWrapperKeyId, EnvVaultAwsKmsSealKeyId, EnvAwsKmsEndpoint, EnvAwsKmsEndpoint} {
			oldVal := os.Getenv(envVar)
			os.Setenv(envVar, "")
			defer os.Setenv(envVar, oldVal)
		}
		wrapperWithMock := NewWrapper()
		wrapperWithMock.client = &mockClient{
			keyId: awsTestKeyId,
		}

		config := map[string]string{
			"disallow_env_vars": "true",
			"kms_key_id":        "a-key-key",
			"access_key":        "a-access-key",
			"secret_key":        "a-secret-key",
			"endpoint":          "my-endpoint",
		}

		_, err := wrapperWithMock.SetConfig(context.Background(), wrapping.WithConfigMap(config))
		require.NoError(t, err)

		require.Equal(t, config["access_key"], wrapperWithMock.accessKey)
		require.Equal(t, config["secret_key"], wrapperWithMock.secretKey)
		require.Equal(t, config["kms_key_id"], wrapperWithMock.keyId)
		require.Equal(t, config["endpoint"], wrapperWithMock.endpoint)
	})

	t.Run("Success - endpoint set automatically", func(t *testing.T) {
		wrapperWithMock := NewWrapper()
		wrapperWithMock.client = &mockClient{
			keyId: awsTestKeyId,
		}
		_, err := wrapperWithMock.SetConfig(t.Context(), WithKeyNotRequired(true))
		require.NoError(t, err)

		c, err := wrapperWithMock.GetAwsKmsClient(t.Context())
		require.NoError(t, err)
		require.Nil(t, c.Options().BaseEndpoint)
	})

	t.Run("Success - custom endpoint set from environment variables", func(t *testing.T) {
		expectedEndpoint := "https://example.com/0"
		oldEndpoint := os.Getenv(EnvAwsKmsEndpoint)
		os.Setenv(EnvAwsKmsEndpoint, expectedEndpoint)
		defer os.Setenv(EnvAwsKmsEndpoint, oldEndpoint)
		wrapperWithMock := NewWrapper()
		wrapperWithMock.client = &mockClient{
			keyId: awsTestKeyId,
		}

		_, err := wrapperWithMock.SetConfig(t.Context(), WithKeyNotRequired(true))
		require.NoError(t, err)

		c, err := wrapperWithMock.GetAwsKmsClient(t.Context())
		require.NoError(t, err)
		assert.Equal(t, expectedEndpoint, *(c.Options().BaseEndpoint))
	})

	t.Run("Success - custom endpoint set from config", func(t *testing.T) {
		expectedEndpoint := "https://example.com/1"

		cfg := map[string]string{
			"endpoint": expectedEndpoint,
		}
		wrapperWithMock := NewWrapper()
		wrapperWithMock.client = &mockClient{
			keyId: awsTestKeyId,
		}

		_, err := wrapperWithMock.SetConfig(t.Context(), wrapping.WithConfigMap(cfg), WithKeyNotRequired(true))
		require.NoError(t, err)

		c, err := wrapperWithMock.GetAwsKmsClient(t.Context())
		require.NoError(t, err)
		assert.Equal(t, expectedEndpoint, *(c.Options().BaseEndpoint))
	})

	t.Run("Success - custom endpoint set from environment variables taking precedence over config", func(t *testing.T) {
		expectedEndpoint := "https://example.com/2"
		oldEndpoint := os.Getenv(EnvAwsKmsEndpoint)
		os.Setenv(EnvAwsKmsEndpoint, expectedEndpoint)
		defer os.Setenv(EnvAwsKmsEndpoint, oldEndpoint)
		wrapperWithMock := NewWrapper()
		wrapperWithMock.client = &mockClient{
			keyId: awsTestKeyId,
		}

		cfg := map[string]string{
			"endpoint": "https://example.com/3",
		}

		_, err := wrapperWithMock.SetConfig(t.Context(), wrapping.WithConfigMap(cfg), WithKeyNotRequired(true))
		require.NoError(t, err)

		c, err := wrapperWithMock.GetAwsKmsClient(t.Context())
		require.NoError(t, err)
		assert.Equal(t, expectedEndpoint, *(c.Options().BaseEndpoint))
	})

	t.Run("Success - concrete client", func(t *testing.T) {
		expectedKeyId := os.Getenv(EnvAwsKmsWrapperKeyId)
		if expectedKeyId == "" {
			expectedKeyId = os.Getenv(EnvVaultAwsKmsSealKeyId)
		}
		if expectedKeyId == "" {
			t.Skip("AWSKMS_WRAPPER_KEY_ID or VAULT_AWSKMS_SEAL_KEY_ID required for concrete SetConfig test")
		}
		if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
			t.Skip("AWS_ACCESS_KEY_ID required for concrete SetConfig test")
		}
		if os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
			t.Skip("AWS_SECRET_ACCESS_KEY required for concrete SetConfig test")
		}
		if os.Getenv("AWS_SESSION_TOKEN") == "" {
			t.Skip("AWS_SESSION_TOKEN required for concrete SetConfig test")
		}
		if os.Getenv("AWS_REGION") == "" {
			t.Skip("AWS_REGION required for concrete SetConfig test")
		}
		w := NewWrapper()

		_, err := w.SetConfig(t.Context())
		require.NoError(t, err)

		// KeyId returns the ARN of the key, rather than the ID portion
		actualKeyId, err := w.KeyId(t.Context())
		require.NoError(t, err)

		keyArn, err := arn.Parse(actualKeyId)
		require.NoError(t, err)
		trimmedActualKeyId, _ := strings.CutPrefix(keyArn.Resource, "key/")
		assert.Equal(t, expectedKeyId, trimmedActualKeyId)
	})
}

func TestEncryptAndDecrypt(t *testing.T) {
	t.Run("Success - mock client", func(t *testing.T) {
		// Works around lack of AWS_REGION var in CI
		if os.Getenv(envAwsRegion) == "" {
			os.Setenv(envAwsRegion, "us-west-2")
			defer os.Setenv(envAwsRegion, "")
		}
		wrapperWithMock := NewWrapper()
		wrapperWithMock.client = &mockClient{
			keyId: awsTestKeyId,
		}
		oldKeyId := os.Getenv(EnvAwsKmsWrapperKeyId)
		os.Setenv(EnvAwsKmsWrapperKeyId, awsTestKeyId)
		defer os.Setenv(EnvAwsKmsWrapperKeyId, oldKeyId)
		encryptionRoundTrip(t, wrapperWithMock)
	})
	// To run the concrete enryption test, the following env variables need to be set:
	//   - AWSKMS_WRAPPER_KEY_ID or VAULT_AWSKMS_SEAL_KEY_ID
	//       - This is the ID of a KMS key in AWS that is symmetric with encrypt & decrypt usage.
	//   - AWS_ACCESS_KEY_ID
	//   - AWS_SECRET_ACCESS_KEY
	//   - AWS_SESSION_TOKEN
	//   - AWS_REGION
	//        - Works around https://hashicorp.atlassian.net/browse/ICU-17849

	t.Run("Success - concrete client", func(t *testing.T) {
		if os.Getenv(EnvAwsKmsWrapperKeyId) == "" && os.Getenv(EnvVaultAwsKmsSealKeyId) == "" {
			t.Skip("AWSKMS_WRAPPER_KEY_ID or VAULT_AWSKMS_SEAL_KEY_ID required for concrete encryption test")
		}
		if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
			t.Skip("AWS_ACCESS_KEY_ID required for concrete encryption test")
		}
		if os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
			t.Skip("AWS_SECRET_ACCESS_KEY required for concrete encryption test")
		}
		if os.Getenv("AWS_SESSION_TOKEN") == "" {
			t.Skip("AWS_SESSION_TOKEN required for concrete encryption test")
		}
		if os.Getenv("AWS_REGION") == "" {
			t.Skip("AWS_REGION required for concrete encryption test")
		}
		w := NewWrapper()

		encryptionRoundTrip(t, w)
	})
}

// Shared profile test setup:
// - Create a role in AWS that whatever role/user you're authenticating as has permission to sts::SetSourceIdentity as
// - Create two profiles in ~/.aws/config
//   - A source profile that has credentials or some method of logging in
//   - A sink profile that uses `source_profile=$YOUR_SOURCE_PROFILE` and `role_arn=$YOUR_NEW_ROLE`
//
// - Set AWS_PROFILE=$SINK_PROFILE (for shared profile through AWS_PROFILE)
// - Set TEST_PROFILE=$SINK_PROFILE (for shared profile through WithSharedCredsProfile)
// - Set AWS_REGION and AWS_KMS_WRAPPER_KEY_ID as above
func TestSharedProfiles(t *testing.T) {
	if os.Getenv("AWS_REGION") == "" {
		t.Skip("AWS_REGION required for shared profiles tests")
	}
	if os.Getenv(EnvAwsKmsWrapperKeyId) == "" && os.Getenv(EnvVaultAwsKmsSealKeyId) == "" {
		t.Skip("AWSKMS_WRAPPER_KEY_ID or VAULT_AWSKMS_SEAL_KEY_ID required for shared profiles tests")
	}

	t.Run("Success - shared profile from WithSharedCredsProfile", func(t *testing.T) {
		prof := os.Getenv("TEST_PROFILE")
		if prof == "" {
			t.Skip("TEST_PROFILE required for shared profile from WithSharedCredsProfile test")
		}
		// Prevent AWS_PROFILE from clobbering this test
		if old := os.Getenv(envAwsProfile); old != "" {
			os.Setenv(envAwsProfile, "")
			defer os.Setenv(envAwsProfile, old)
		}

		w := NewWrapper()

		_, err := w.SetConfig(t.Context(), WithSharedCredsProfile(prof))
		require.NoError(t, err)

		encryptionRoundTrip(t, w)
	})

	t.Run("Success - shared profile from AWS_PROFILE", func(t *testing.T) {
		// Default awskms config pulls shared creds from AWS_PROFILE if it's set
		if os.Getenv(envAwsProfile) == "" {
			t.Skip("AWS_PROFILE required for shared profile from AWS_PROFILE test")
		}

		w := NewWrapper()
		_, err := w.SetConfig(t.Context())
		require.NoError(t, err)
		encryptionRoundTrip(t, w)
	})

	t.Run("Failure - no shared config", func(t *testing.T) {
		if old := os.Getenv(envAwsProfile); old != "" {
			os.Setenv(envAwsProfile, "")
			defer os.Setenv(envAwsProfile, old)
		}

		w := NewWrapper()

		_, err := w.SetConfig(t.Context(), WithSharedCredsProfile("this-profile-definitely-doesn't-exist"))
		require.Error(t, err)
	})
}

func encryptionRoundTrip(t *testing.T, w *Wrapper) {
	_, err := w.SetConfig(t.Context())
	require.NoError(t, err)

	expected := []byte("foo")
	swi, err := w.Encrypt(context.Background(), expected, nil)
	require.NoError(t, err)

	output, err := w.Decrypt(context.Background(), swi, nil)
	require.NoError(t, err)
	assert.Equal(t, expected, output)
}
