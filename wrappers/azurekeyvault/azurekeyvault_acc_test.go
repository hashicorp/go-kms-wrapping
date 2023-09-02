// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azurekeyvault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
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
	s := NewWrapper()
	client := keyvault.New()
	s.client = &client

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

func Test_getKeyVaultClient(t *testing.T) {
	t.Parallel()
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
	s := NewWrapper()
	_, err := s.SetConfig(
		context.Background(),
		wrapping.WithConfigMap(config),
		WithKeyNotRequired(true),
	)
	require.NoError(t, err)
	t.Run("send-decorators-set", func(t *testing.T) {
		// let's at least ensure that the custom SendDecorator is being properly
		// set.
		t.Parallel()
		got, err := s.getKeyVaultClient(nil)
		require.NoError(t, err)
		assert.NotEmpty(t, got.SendDecorators)
	})
	t.Run("force-tls-error", func(t *testing.T) {
		// not great, but this test will at least ensure that the client's
		// custom TLS transport is being used
		t.Parallel()
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(fmt.Sprintf("version: %s", tls.VersionName(r.TLS.Version))))
		}))
		ts.TLS = &tls.Config{
			MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS10,
		}
		ts.StartTLS()
		defer ts.Close()

		certPool := x509.NewCertPool()
		certPool.AddCert(ts.Certificate())

		assert.NoError(t, err)
		client, err := s.getKeyVaultClient(certPool)
		require.NoError(t, err)
		assert.NotEmpty(t, client.SendDecorators)
		client.Authorizer = &authorizer{}
		_, err = client.GetKey(context.Background(), ts.URL, "global", "1")
		require.Error(t, err)
		assert.ErrorContains(t, err, "tls: protocol version not supported")
	})
}

type authorizer struct{}

func (*authorizer) WithAuthorization() autorest.PrepareDecorator {
	return autorest.WithNothing()
}
