// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azurekeyvault

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/Azure/go-autorest/autorest/azure"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

func TestAzureKeyVault_SetConfig(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	tenantID := os.Getenv("AZURE_TENANT_ID")
	os.Unsetenv("AZURE_TENANT_ID")

	// Attempt to set config, expect failure due to missing config
	_, err := s.SetConfig(context.Background())
	if err == nil {
		t.Fatal("expected error when Azure Key Vault config values are not provided")
	}

	os.Setenv("AZURE_TENANT_ID", tenantID)

	_, err = s.SetConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestAzureKeyVault_IgnoreEnv(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	expectedErr := `error fetching Azure Key Vault wrapper key information: Get "https://a-vault-name.a-resource/keys/a-key-name/?api-version=7.3": dial tcp: lookup a-vault-name.a-resource: no such host`

	s := NewWrapper()

	// Setup environment values to ignore for the following values
	for _, envVar := range []string{
		"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
		"AZURE_ENVIRONMENT", "AZURE_AD_RESOURCE", EnvAzureKeyVaultWrapperVaultName,
		EnvVaultAzureKeyVaultVaultName, EnvAzureKeyVaultWrapperKeyName, EnvVaultAzureKeyVaultKeyName,
	} {
		oldVal := os.Getenv(envVar)
		os.Setenv(envVar, "envValue")
		defer os.Setenv(envVar, oldVal)
	}
	config := map[string]string{
		"disallow_env_vars": "true",
		"tenant_id":         "a-tenant-id",
		"client_id":         "a-client-id",
		"client_secret":     "a-client-secret",
		"environment":       azure.PublicCloud.Name,
		"resource":          "a-resource",
		"vault_name":        "a-vault-name",
		"key_name":          "a-key-name",
	}
	_, err := s.SetConfig(context.Background(), wrapping.WithConfigMap(config))
	require.Equal(t, expectedErr, err.Error())
	require.Equal(t, config["tenant_id"], s.tenantID)
	require.Equal(t, config["client_id"], s.clientID)
	require.Equal(t, config["client_secret"], s.clientSecret)
	require.Equal(t, config["environment"], s.environment.Name)
	require.Equal(t, "https://"+config["resource"]+"/", s.resource)
	require.Equal(t, config["vault_name"], s.vaultName)
	require.Equal(t, config["key_name"], s.keyName)
}

func TestAzureKeyVault_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	_, err := s.SetConfig(context.Background())
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := s.Decrypt(context.Background(), swi, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}
