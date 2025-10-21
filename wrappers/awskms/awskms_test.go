// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awskms

import (
	"context"
	"os"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/suite"

	"go.uber.org/mock/gomock"
)

const (
	awsTestKeyId  = "foo"
	envAwsProfile = "AWS_PROFILE"
	envAwsRegion  = "AWS_REGION"
)

type AwsKmsSuite struct {
	suite.Suite
	ctrl            *gomock.Controller
	wrapperWithMock *Wrapper
}

func TestSuite(t *testing.T) {
	suite.Run(t, new(AwsKmsSuite))
}

func (s *AwsKmsSuite) SetupSubTest() {
	s.ctrl = gomock.NewController(s.T())
	s.wrapperWithMock = NewWrapper()
	s.wrapperWithMock.client = &mockClient{
		keyId: awsTestKeyId,
	}
}

func (s *AwsKmsSuite) TestSetConfig() {
	// Works around lack of AWS_REGION var in CI
	if os.Getenv(envAwsRegion) == "" {
		os.Setenv(envAwsRegion, "us-west-2")
		defer os.Setenv(envAwsRegion, "")
	}

	s.Run("Failure - No wrapper key ID", func() {
		oldKeyId := os.Getenv(EnvAwsKmsWrapperKeyId)
		os.Setenv(EnvAwsKmsWrapperKeyId, "")
		defer os.Setenv(EnvAwsKmsWrapperKeyId, oldKeyId)

		_, err := s.wrapperWithMock.SetConfig(context.Background())
		s.Require().Error(err, "expected error when AwsKms wrapping key ID is not provided")
	})

	s.Run("Success - Test key ID pulled from environment variables", func() {
		oldKeyId := os.Getenv(EnvAwsKmsWrapperKeyId)
		os.Setenv(EnvAwsKmsWrapperKeyId, awsTestKeyId)
		defer os.Setenv(EnvAwsKmsWrapperKeyId, oldKeyId)

		_, err := s.wrapperWithMock.SetConfig(context.Background())
		s.Require().NoError(err)
	})

	s.Run("Success - Ignore environment variables", func() {
		// Setup environment values to ignore for the following values
		for _, envVar := range []string{EnvAwsKmsWrapperKeyId, EnvVaultAwsKmsSealKeyId, EnvAwsKmsEndpoint, EnvAwsKmsEndpoint} {
			oldVal := os.Getenv(envVar)
			os.Setenv(envVar, "")
			defer os.Setenv(envVar, oldVal)
		}

		config := map[string]string{
			"disallow_env_vars": "true",
			"kms_key_id":        "a-key-key",
			"access_key":        "a-access-key",
			"secret_key":        "a-secret-key",
			"endpoint":          "my-endpoint",
		}

		_, err := s.wrapperWithMock.SetConfig(context.Background(), wrapping.WithConfigMap(config))
		s.Require().NoError(err)

		s.Require().Equal(config["access_key"], s.wrapperWithMock.accessKey)
		s.Require().Equal(config["secret_key"], s.wrapperWithMock.secretKey)
		s.Require().Equal(config["kms_key_id"], s.wrapperWithMock.keyId)
		s.Require().Equal(config["endpoint"], s.wrapperWithMock.endpoint)
	})

	s.Run("Success - endpoint set automatically", func() {
		_, err := s.wrapperWithMock.SetConfig(s.T().Context(), WithKeyNotRequired(true))
		s.Require().NoError(err)

		c, err := s.wrapperWithMock.GetAwsKmsClient(s.T().Context())
		s.Require().NoError(err)
		s.Assert().Nil(c.Options().BaseEndpoint)
	})

	s.Run("Success - custom endpoint set from environment variables", func() {
		expectedEndpoint := "https://example.com/0"
		oldEndpoint := os.Getenv(EnvAwsKmsEndpoint)
		os.Setenv(EnvAwsKmsEndpoint, expectedEndpoint)
		defer os.Setenv(EnvAwsKmsEndpoint, oldEndpoint)

		_, err := s.wrapperWithMock.SetConfig(s.T().Context(), WithKeyNotRequired(true))
		s.Require().NoError(err)

		c, err := s.wrapperWithMock.GetAwsKmsClient(s.T().Context())
		s.Require().NoError(err)
		s.Assert().Equal(expectedEndpoint, *(c.Options().BaseEndpoint))
	})

	s.Run("Success - custom endpoint set from config", func() {
		expectedEndpoint := "https://example.com/1"

		cfg := map[string]string{
			"endpoint": expectedEndpoint,
		}

		_, err := s.wrapperWithMock.SetConfig(s.T().Context(), wrapping.WithConfigMap(cfg), WithKeyNotRequired(true))
		s.Require().NoError(err)

		c, err := s.wrapperWithMock.GetAwsKmsClient(s.T().Context())
		s.Require().NoError(err)
		s.Assert().Equal(expectedEndpoint, *(c.Options().BaseEndpoint))
	})

	s.Run("Success - custom endpoint set from environment variables taking precedence over config", func() {
		expectedEndpoint := "https://example.com/2"
		oldEndpoint := os.Getenv(EnvAwsKmsEndpoint)
		os.Setenv(EnvAwsKmsEndpoint, expectedEndpoint)
		defer os.Setenv(EnvAwsKmsEndpoint, oldEndpoint)

		cfg := map[string]string{
			"endpoint": "https://example.com/3",
		}

		_, err := s.wrapperWithMock.SetConfig(s.T().Context(), wrapping.WithConfigMap(cfg), WithKeyNotRequired(true))
		s.Require().NoError(err)

		c, err := s.wrapperWithMock.GetAwsKmsClient(s.T().Context())
		s.Require().NoError(err)
		s.Assert().Equal(expectedEndpoint, *(c.Options().BaseEndpoint))
	})
}

func (s *AwsKmsSuite) TestEncryptAndDecrypt() {
	s.Run("Success - mock client", func() {
		// Works around lack of AWS_REGION var in CI
		if os.Getenv(envAwsRegion) == "" {
			os.Setenv(envAwsRegion, "us-west-2")
			defer os.Setenv(envAwsRegion, "")
		}
		oldKeyId := os.Getenv(EnvAwsKmsWrapperKeyId)
		os.Setenv(EnvAwsKmsWrapperKeyId, awsTestKeyId)
		defer os.Setenv(EnvAwsKmsWrapperKeyId, oldKeyId)
		encryptionRoundTrip(s, s.wrapperWithMock)
	})
	// To run the concrete enryption test, the following env variables need to be set:
	//   - AWSKMS_WRAPPER_KEY_ID or VAULT_AWSKMS_SEAL_KEY_ID
	//       - This is the ID of a KMS key in AWS that is symmetric with encrypt & decrypt usage.
	//   - AWS_ACCESS_KEY_ID
	//   - AWS_SECRET_ACCESS_KEY
	//   - AWS_SESSION_TOKEN
	//   - AWS_REGION
	//        - Works around https://hashicorp.atlassian.net/browse/ICU-17849

	s.Run("Success - concrete client", func() {
		if os.Getenv(EnvAwsKmsWrapperKeyId) == "" && os.Getenv(EnvVaultAwsKmsSealKeyId) == "" {
			s.T().Skip("AWSKMS_WRAPPER_KEY_ID or VAULT_AWSKMS_SEAL_KEY_ID required for concrete encryption test")
		}
		if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
			s.T().Skip("AWS_ACCESS_KEY_ID required for concrete encryption test")
		}
		if os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
			s.T().Skip("AWS_SECRET_ACCESS_KEY required for concrete encryption test")
		}
		if os.Getenv("AWS_SESSION_TOKEN") == "" {
			s.T().Skip("AWS_SESSION_TOKEN required for concrete encryption test")
		}
		if os.Getenv("AWS_REGION") == "" {
			s.T().Skip("AWS_REGION required for concrete encryption test")
		}
		w := NewWrapper()

		encryptionRoundTrip(s, w)
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
func (s *AwsKmsSuite) TestSharedProfiles() {
	if os.Getenv("AWS_REGION") == "" {
		s.T().Skip("AWS_REGION required for shared profiles tests")
	}
	if os.Getenv(EnvAwsKmsWrapperKeyId) == "" && os.Getenv(EnvVaultAwsKmsSealKeyId) == "" {
		s.T().Skip("AWSKMS_WRAPPER_KEY_ID or VAULT_AWSKMS_SEAL_KEY_ID required for shared profiles tests")
	}

	s.Run("Success - shared profile from WithSharedCredsProfile", func() {
		prof := os.Getenv("TEST_PROFILE")
		if prof == "" {
			s.T().Skip("TEST_PROFILE required for shared profile from WithSharedCredsProfile test")
		}
		// Prevent AWS_PROFILE from clobbering this test
		if old := os.Getenv(envAwsProfile); old != "" {
			os.Setenv(envAwsProfile, "")
			defer os.Setenv(envAwsProfile, old)
		}

		w := NewWrapper()

		_, err := w.SetConfig(s.T().Context(), WithSharedCredsProfile(prof))
		s.Require().NoError(err)

		encryptionRoundTrip(s, w)
	})

	s.Run("Success - shared profile from AWS_PROFILE", func() {
		// Default awskms config pulls shared creds from AWS_PROFILE if it's set
		if os.Getenv(envAwsProfile) == "" {
			s.T().Skip("AWS_PROFILE required for shared profile from AWS_PROFILE test")
		}

		w := NewWrapper()
		_, err := w.SetConfig(s.T().Context())
		s.Require().NoError(err)
		encryptionRoundTrip(s, w)
	})

	s.Run("Failure - no shared config", func() {
		if old := os.Getenv(envAwsProfile); old != "" {
			os.Setenv(envAwsProfile, "")
			defer os.Setenv(envAwsProfile, old)
		}

		w := NewWrapper()

		_, err := w.SetConfig(s.T().Context(), WithSharedCredsProfile("this-profile-definitely-doesn't-exist"))
		s.Require().Error(err)
	})

}

func encryptionRoundTrip(s *AwsKmsSuite, w *Wrapper) {
	_, err := w.SetConfig(s.T().Context())
	s.Require().NoError(err)

	expected := []byte("foo")
	swi, err := w.Encrypt(context.Background(), expected, nil)
	s.Require().NoError(err)

	output, err := w.Decrypt(context.Background(), swi, nil)
	s.Require().NoError(err)
	s.Assert().Equal(expected, output)
}
