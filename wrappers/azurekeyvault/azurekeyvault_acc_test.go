package azurekeyvault

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureKeyVault_SetConfig(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	s := NewWrapper(nil)
	tenantID := os.Getenv("AZURE_TENANT_ID")
	os.Unsetenv("AZURE_TENANT_ID")

	// Attempt to set config, expect failure due to missing config
	_, err := s.SetConfig(nil)
	if err == nil {
		t.Fatal("expected error when Azure Key Vault config values are not provided")
	}

	os.Setenv("AZURE_TENANT_ID", tenantID)

	_, err = s.SetConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAzureKeyVault_IgnoreEnv(t *testing.T) {
	s := NewWrapper(nil)
	client := keyvault.New()
	s.client = &client

	// Setup environment values to ignore for the following values
	for _, envVar := range []string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
		"AZURE_ENVIRONMENT", "AZURE_AD_RESOURCE", EnvAzureKeyVaultWrapperVaultName,
		EnvVaultAzureKeyVaultVaultName, EnvAzureKeyVaultWrapperKeyName, EnvVaultAzureKeyVaultKeyName} {
		oldVal := os.Getenv(envVar)
		os.Setenv(envVar, "envValue")
		defer os.Setenv(envVar, oldVal)
	}
	config := map[string]string{
		"tenant_id":     "a-tenant-id",
		"client_id":     "a-client-id",
		"client_secret": "a-client-secret",
		"environment":   azure.PublicCloud.Name,
		"resource":      "a-resource",
		"vault_name":    "a-vault-name",
		"key_name":      "a-key-name",
	}
	_, err := s.SetConfigWithEnv(config, false)
	assert.NoError(t, err)
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

	s := NewWrapper(nil)
	_, err := s.SetConfig(nil)
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
