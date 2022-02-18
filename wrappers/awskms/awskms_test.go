package awskms

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSKMSWrapper(t *testing.T) {
	s := NewWrapper(nil)
	s.client = &mockClient{
		keyID: aws.String(awsTestKeyID),
	}

	_, err := s.SetConfig(nil)
	if err == nil {
		t.Fatal("expected error when AWSKMS wrapping key ID is not provided")
	}

	// Set the key
	oldKeyID := os.Getenv(EnvAWSKMSWrapperKeyID)
	os.Setenv(EnvAWSKMSWrapperKeyID, awsTestKeyID)
	defer os.Setenv(EnvAWSKMSWrapperKeyID, oldKeyID)
	_, err = s.SetConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAWSKMSWrapper_IgnoreEnv(t *testing.T) {
	wrapper := NewAWSKMSTestWrapper()

	// Setup environment values to ignore for the following values
	for _, envVar := range []string{EnvAWSKMSWrapperKeyID, EnvVaultAWSKMSSealKeyID, "AWS_KMS_ENDPOINT"} {
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

	_, err := wrapper.SetConfig(config)
	assert.NoError(t, err)

	require.Equal(t, config["access_key"], wrapper.accessKey)
	require.Equal(t, config["secret_key"], wrapper.secretKey)
	require.Equal(t, config["kms_key_id"], wrapper.keyID)
	require.Equal(t, config["endpoint"], wrapper.endpoint)
}

func TestAWSKMSWrapper_Lifecycle(t *testing.T) {
	if os.Getenv(EnvAWSKMSWrapperKeyID) == "" && os.Getenv(EnvVaultAWSKMSSealKeyID) == "" {
		t.SkipNow()
	}
	s := NewWrapper(nil)
	s.client = &mockClient{
		keyID: aws.String(awsTestKeyID),
	}
	oldKeyID := os.Getenv(EnvAWSKMSWrapperKeyID)
	os.Setenv(EnvAWSKMSWrapperKeyID, awsTestKeyID)
	defer os.Setenv(EnvAWSKMSWrapperKeyID, oldKeyID)
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
func TestAccAWSKMSWrapper_Lifecycle(t *testing.T) {
	if os.Getenv(EnvAWSKMSWrapperKeyID) == "" && os.Getenv(EnvVaultAWSKMSSealKeyID) == "" {
		t.SkipNow()
	}
	s := NewWrapper(nil)
	testEncryptionRoundTrip(t, s)
}

func testEncryptionRoundTrip(t *testing.T, w *Wrapper) {
	w.SetConfig(nil)
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

func TestAWSKMSWrapper_custom_endpoint(t *testing.T) {
	customEndpoint := "https://custom.endpoint"
	customEndpoint2 := "https://custom.endpoint.2"
	endpointENV := "AWS_KMS_ENDPOINT"

	// unset at end of test
	os.Setenv(EnvAWSKMSWrapperKeyID, awsTestKeyID)
	defer func() {
		if err := os.Unsetenv(EnvAWSKMSWrapperKeyID); err != nil {
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
			s := NewWrapper(nil)

			s.client = &mockClient{
				keyID: aws.String(awsTestKeyID),
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
			if _, err := s.SetConfig(cfg); err != nil {
				t.Fatalf("error setting config: %s", err)
			}

			// call GetAWSKMSClient() to get the configured client and verify it's
			// endpoint
			k, err := s.GetAWSKMSClient()
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
