package ibmkp

// These tests execute real calls. They require:
// 1. IBM Cloud account
//    https://cloud.ibm.com/docs/overview?topic=overview-quickstart_lite
//
// 2. IBM Key Protect instance
//    https://cloud.ibm.com/docs/key-protect?topic=key-protect-provision
//
// 3. IBM Key Protect's Root Key
//    https://cloud.ibm.com/docs/key-protect?topic=key-protect-create-root-keys
//
// 4. IBM Cloud Service ID with an API Key.
//    https://cloud.ibm.com/docs/account?topic=account-serviceids
//
// 5. Grant 'Reader' access to Service ID (step 4) into Root Key (step 3)
//    https://cloud.ibm.com/docs/key-protect?topic=key-protect-grant-access-keys
//
// No costs are involved to setup IBM Cloud environment because IBM Cloud account
// can be created for free and IBM Key Protect allows up to 20 keys for free.
//
// To run this test, the following env variables need to be set:
//   - IBMCLOUD_API_KEY created on step 4
//   - IBMCLOUD_KP_INSTANCE_ID created on step 2, it is 8th field on CRN.
//   - IBMCLOUD_KP_KEY_ID created on step 3

import (
	"context"
	"crypto/subtle"
	"os"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	TestIbmApiKey       = "notARealApiKey"
	TestIbmKpInstanceId = "a6493c3a-5b29-4ac3-9eaa-deadbeef3bfd"
	TestIbmKpKeyId      = "1234abcd-abcd-asdf-3dea-beefdeadabcd"
)

func TestIbmKp_SetConfig(t *testing.T) {
	checkAndSetEnvVars(t)

	s := NewWrapper()
	instanceID := os.Getenv(EnvIbmKpInstanceId)
	os.Unsetenv(EnvIbmKpInstanceId)

	// Attempt to set config, expect failure due to missing config
	_, err := s.SetConfig(context.Background())
	if err == nil {
		t.Fatal("expected error when IBM Key Protect Key Vault config values are not provided")
	}

	os.Setenv(EnvIbmKpInstanceId, instanceID)

	_, err = s.SetConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

// This test does not need environment setup
func TestIbmKp_IgnoreEnv(t *testing.T) {
	wrapper := NewWrapper()
	client, _ := wrapper.GetIbmKpClient()
	wrapper.client = client

	// Setup environment values to ignore for the following values
	for _, envVar := range []string{EnvIbmApiKey, EnvIbmKpEndpoint, EnvIbmKpInstanceId, EnvIbmKpKeyId} {
		oldVal := os.Getenv(envVar)
		os.Setenv(envVar, "envValue")
		defer os.Setenv(envVar, oldVal)
	}

	config := map[string]string{
		"disallow_env_vars": "true",
		"api_key":           "a-api-key",
		"instance_id":       "a-instance-id",
		"endpoint":          "my-endpoint",
	}

	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(config), wrapping.WithKeyId("a-key-key"))
	assert.NoError(t, err)

	require.Equal(t, config["api_key"], wrapper.apiKey)
	require.Equal(t, config["instance_id"], wrapper.instanceId)
	require.Equal(t, "a-key-key", wrapper.keyId)
	require.Equal(t, config["endpoint"], wrapper.endpoint)
}

func TestIbmKp_Lifecycle(t *testing.T) {
	checkAndSetEnvVars(t)

	s := NewWrapper()
	_, err := s.SetConfig(context.Background())
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("error encrypting: %s", err.Error())
	}

	pt, err := s.Decrypt(context.Background(), swi, nil)
	if err != nil {
		t.Fatalf("error decrypting: %s", err.Error())
	}

	if subtle.ConstantTimeCompare(input, pt) == 1 {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}

// checkAndSetEnvVars check and sets the required env vars. It will skip tests that are
// not ran as acceptance tests since they require calling to external APIs.
func checkAndSetEnvVars(t *testing.T) {
	t.Helper()

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.Skip("Skipping, env var 'VAULT_ACC' is empty")
	}

	if os.Getenv(EnvIbmApiKey) == "" {
		os.Setenv(EnvIbmApiKey, TestIbmApiKey)
	}

	if os.Getenv(EnvIbmKpInstanceId) == "" {
		os.Setenv(EnvIbmKpInstanceId, TestIbmKpInstanceId)
	}

	if os.Getenv(EnvIbmKpKeyId) == "" {
		os.Setenv(EnvIbmKpKeyId, TestIbmKpKeyId)
	}
}
