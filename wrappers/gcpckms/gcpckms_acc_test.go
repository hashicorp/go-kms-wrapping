// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpckms

import (
	"os"
	"reflect"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	context "golang.org/x/net/context"
)

const (
	// These values need to match the values from the hc-value-testing project
	gcpckmsTestProjectID  = "hc-vault-testing"
	gcpckmsTestLocationID = "global"
	gcpckmsTestKeyRing    = "vault-test-keyring"
	gcpckmsTestCryptoKey  = "vault-test-key"
)

// TestGcpKeyIdAfterConfig will test the result of calling the wrapper's KeyId()
// after it's configured with various options
func TestGcpKeyIdAfterConfig(t *testing.T) {
	// Now test for cases where CKMS values are provided
	checkAndSetEnvVars(t)
	ctx := context.Background()

	tests := []struct {
		name        string
		opts        []wrapping.Option
		expectKeyId bool
	}{
		{
			name: "expected-key-id",
			opts: []wrapping.Option{
				wrapping.WithConfigMap(map[string]string{"credentials": os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")}),
			},
			expectKeyId: true,
		},
		{
			name: "unexpected-key-id",
			opts: []wrapping.Option{
				wrapping.WithConfigMap(map[string]string{"credentials": os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")}),
				WithKeyNotRequired(true),
			},
			expectKeyId: false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := NewWrapper()
			_, err := s.SetConfig(ctx, tc.opts...)
			if err != nil {
				t.Fatalf("error setting seal config: %v", err)
			}
			id, err := s.KeyId(ctx)
			if err != nil {
				t.Fatalf("unexpected error getting key id: %v", err)
			}
			switch {
			case tc.expectKeyId:
				if id == "" {
					t.Fatalf("expected an id")
				}
				// Test KeyId after Encrypt call
				input := []byte("foo")
				swi, err := s.Encrypt(context.Background(), input)
				if err != nil {
					t.Fatalf("err: %s", err.Error())
				}
				if swi.KeyInfo.KeyId != id {
					t.Fatalf("expected %s got: %s", id, swi.KeyInfo.KeyId)
				}
				postEncryptKeyId, err := s.KeyId(ctx)
				if err != nil {
					t.Fatalf("err: %s", err.Error())
				}
				if swi.KeyInfo.KeyId != postEncryptKeyId {
					t.Fatalf("expected key info id %s to equal key id %s", swi.KeyInfo.KeyId, postEncryptKeyId)
				}

			default:
				if id != "" {
					t.Fatalf("unexpected id was: %s", id)
				}
			}
		})
	}
}

// TestDisableEnv makes sure that we properly get all our settings from a configuration
// map instead of the environment variables
func TestDisableEnv(t *testing.T) {
	// Now test for cases where CKMS values are provided
	checkAndSetEnvVars(t)

	configMap := map[string]string{
		"project":    os.Getenv(EnvGcpCkmsWrapperProject),
		"region":     os.Getenv(EnvGcpCkmsWrapperLocation),
		"key_ring":   os.Getenv(EnvGcpCkmsWrapperKeyRing),
		"crypto_key": os.Getenv(EnvGcpCkmsWrapperCryptoKey),
	}

	// Reset the env values to validate we are using the config map ones
	t.Setenv(EnvGcpCkmsWrapperProject, "bad_project")
	t.Setenv(EnvGcpCkmsWrapperLocation, "bad_location")
	t.Setenv(EnvGcpCkmsWrapperKeyRing, "bad_key_ring")
	t.Setenv(EnvGcpCkmsWrapperCryptoKey, "bad_crypto_key")
	t.Setenv(EnvVaultGcpCkmsSealKeyRing, "bad_vault_key_ring")
	t.Setenv(EnvVaultGcpCkmsSealCryptoKey, "bad_vault_crypto_key")

	s := NewWrapper()
	_, err := s.SetConfig(context.Background(), wrapping.WithConfigMap(configMap), wrapping.WithDisallowEnvVars(true))
	if err != nil {
		t.Fatalf("got error from SetConfig %v", err)
	}

	// Make sure we can use the key properly.
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

func TestGcpCkmsSeal(t *testing.T) {
	t.Setenv(EnvGcpCkmsWrapperProject, "") // Make sure at least one required value is not set.

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

	// assert the wrappers key id matches the key id used for encryption
	keyId, err := s.KeyId(context.Background())
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if swi.KeyInfo.KeyId != keyId {
		t.Fatalf("expected %s got: %s", keyId, swi.KeyInfo.KeyId)
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
