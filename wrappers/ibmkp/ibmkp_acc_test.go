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
// 4. IBM Cloud Service ID with an API Key
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
//   - IBMCLOUD_KP_INSTANCE_ID created on step 2
//   - IBMCLOUD_KP_KEY_ID created on step 3

import (
	"context"
	"os"
	"reflect"
	"testing"
)

const (
	TestIBMApiKey       = "notARealApiKey"
	TestIBMKPInstanceID = "a6493c3a-5b29-4ac3-9eaa-deadbeef3bfd"
	TestIBMKPKeyID      = "1234abcd-abcd-asdf-3dea-beefdeadabcd"
)

func TestIBMKP_SetConfig(t *testing.T) {

	checkAndSetEnvVars(t)

	s := NewWrapper(nil)
	instanceID := os.Getenv(EnvIBMKPInstanceID)
	os.Unsetenv(EnvIBMKPInstanceID)

	// Attempt to set config, expect failure due to missing config
	_, err := s.SetConfig(nil)
	if err == nil {
		t.Fatal("expected error when IBM Key Protect Key Vault config values are not provided")
	}

	os.Setenv(EnvIBMKPInstanceID, instanceID)

	_, err = s.SetConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestIBMKP_Lifecycle(t *testing.T) {

	checkAndSetEnvVars(t)

	s := NewWrapper(nil)
	_, err := s.SetConfig(nil)
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

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}

// checkAndSetEnvVars check and sets the required env vars. It will skip tests that are
// not ran as acceptance tests since they require calling to external APIs.
func checkAndSetEnvVars(t *testing.T) {
	t.Helper()

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	if os.Getenv(EnvIBMApiKey) == "" {
		os.Setenv(EnvIBMApiKey, TestIBMApiKey)
	}

	if os.Getenv(EnvIBMKPInstanceID) == "" {
		os.Setenv(EnvIBMKPInstanceID, TestIBMKPInstanceID)
	}

	if os.Getenv(EnvIBMKPKeyID) == "" {
		os.Setenv(EnvIBMKPKeyID, TestIBMKPKeyID)
	}
}
