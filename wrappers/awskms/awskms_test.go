package awskms

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAwsKmsWrapper(t *testing.T) {
	s := NewWrapper()
	s.client = &mockClient{
		keyId: aws.String(awsTestKeyId),
	}

	_, err := s.SetConfig(nil)
	if err == nil {
		t.Fatal("expected error when AwsKms wrapping key ID is not provided")
	}

	// Set the key
	oldKeyId := os.Getenv(EnvAwsKmsWrapperKeyId)
	os.Setenv(EnvAwsKmsWrapperKeyId, awsTestKeyId)
	defer os.Setenv(EnvAwsKmsWrapperKeyId, oldKeyId)
	_, err = s.SetConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAwsKmsWrapper_IgnoreEnv(t *testing.T) {
	wrapper := NewAwsKmsTestWrapper()

	// Setup environment values to ignore for the following values
	for _, envVar := range []string{EnvAwsKmsWrapperKeyId, EnvVaultAwsKmsSealKeyId, "AWS_KMS_ENDPOINT"} {
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
	s := NewWrapper()
	s.client = &mockClient{
		keyId: aws.String(awsTestKeyId),
	}
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
//   - AWSKMS_WRAPPING_KEY_ID or VAULT_AWSKMS_SEAL_KEY_ID
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
	endpointENV := "AWS_KMS_ENDPOINT"

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
		Expected *string
	}{
		{
			// Default will have nil for the config endpoint, and be looked up
			// dynamically by the SDK
			Title: "Default",
		},
		{
			Title:    "Environment",
			Env:      customEndpoint,
			Expected: aws.String(customEndpoint),
		},
		{
			Title:    "Config",
			Config:   cfg,
			Expected: aws.String(customEndpoint),
		},
		{
			// Expect environment to take precedence over configuration
			Title:    "Env-Config",
			Env:      customEndpoint2,
			Config:   cfg,
			Expected: aws.String(customEndpoint2),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Title, func(t *testing.T) {
			s := NewWrapper()

			s.client = &mockClient{
				keyId: aws.String(awsTestKeyId),
			}

			if tc.Env != "" {
				if err := os.Setenv(endpointENV, tc.Env); err != nil {
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

			// call GetAwsKmsClient() to get the configured client and verify it's
			// endpoint
			k, err := s.GetAwsKmsClient()
			if err != nil {
				t.Fatal(err)
			}

			if tc.Expected == nil && k.Config.Endpoint != nil {
				t.Fatalf("Expected nil endpoint, got: (%s)", *k.Config.Endpoint)
			}

			if tc.Expected != nil {
				if k.Config.Endpoint == nil {
					t.Fatal("expected custom endpoint, but config was nil")
				}
				if *k.Config.Endpoint != *tc.Expected {
					t.Fatalf("expected custom endpoint (%s), got: (%s)", *tc.Expected, *k.Config.Endpoint)
				}
			}

			// clear endpoint env after each test
			if err := os.Unsetenv(endpointENV); err != nil {
				t.Fatal(err)
			}
		})
	}
}
