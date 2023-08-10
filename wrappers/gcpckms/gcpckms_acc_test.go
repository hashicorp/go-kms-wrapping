// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package gcpckms

import (
	"os"
	"reflect"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	context "golang.org/x/net/context"
)

const (
	// These values need to match the values from the hc-value-testing project
	gcpckmsTestProjectID  = "hc-vault-testing"
	gcpckmsTestLocationID = "global"
	gcpckmsTestKeyRing    = "vault-test-keyring"
	gcpckmsTestCryptoKey  = "vault-test-key"
)

func TestGcpCkmsSeal(t *testing.T) {
	// Do an error check before env vars are set
	s := NewWrapper()
	_, err := s.SetConfig(context.Background())
	if err == nil {
		t.Fatal("expected error when GcpCkmsSeal required values are not provided")
	}

	// Now test for cases where CKMS values are provided
	checkAndSetEnvVars(t)

	configCases := map[string]map[string]string{
		"env_var": nil,
		"config": {
			"credentials": os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
		},
	}

	for name, config := range configCases {
		t.Run(name, func(t *testing.T) {
			s := NewWrapper()
			_, err := s.SetConfig(context.Background(), wrapping.WithConfigMap(config))
			if err != nil {
				t.Fatalf("error setting seal config: %v", err)
			}
		})
	}
}

func TestGcpCkmsSeal_Lifecycle(t *testing.T) {
	checkAndSetEnvVars(t)

	s := NewWrapper()
	_, err := s.SetConfig(context.Background())
	if err != nil {
		t.Fatalf("error setting seal config: %v", err)
	}

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := s.Decrypt(context.Background(), swi)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
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

	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" && os.Getenv(EnvGcpCkmsWrapperCredsPath) == "" {
		t.Fatal("unable to get GCP credentials via environment variables")
	}

	if os.Getenv(EnvGcpCkmsWrapperProject) == "" {
		os.Setenv(EnvGcpCkmsWrapperProject, gcpckmsTestProjectID)
	}

	if os.Getenv(EnvGcpCkmsWrapperLocation) == "" {
		os.Setenv(EnvGcpCkmsWrapperLocation, gcpckmsTestLocationID)
	}

	if os.Getenv(EnvVaultGcpCkmsSealKeyRing) == "" {
		os.Setenv(EnvVaultGcpCkmsSealKeyRing, gcpckmsTestKeyRing)
	}
	if os.Getenv(EnvGcpCkmsWrapperKeyRing) == "" {
		os.Setenv(EnvGcpCkmsWrapperKeyRing, gcpckmsTestKeyRing)
	}

	if os.Getenv(EnvVaultGcpCkmsSealCryptoKey) == "" {
		os.Setenv(EnvVaultGcpCkmsSealCryptoKey, gcpckmsTestCryptoKey)
	}
	if os.Getenv(EnvGcpCkmsWrapperCryptoKey) == "" {
		os.Setenv(EnvGcpCkmsWrapperCryptoKey, gcpckmsTestCryptoKey)
	}
}
