package azurekeyvault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest/to"
	wrapping "github.com/hashicorp/go-kms-wrapping"
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

// TestAzureKeyVault_KeyLifecycle tests implementations of the
// wrapping.LifecycleWrapper interface methods for Azure Key Vault.
func TestAzureKeyVault_KeyLifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	ctx := context.Background()

	// Configure the wrapper
	opts := &wrapping.WrapperOptions{KeyNotRequired: true}
	s := NewWrapper(opts)
	_, err := s.SetConfig(nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	// Generate an RSA key to import
	rsa1 := testGenerateRSAKey(t)

	// Create a KMSKey containing the RSA key
	kmsKey := wrapping.KMSKey{
		Type:            wrapping.RSA2048,
		ProtectionLevel: wrapping.HSM,
		Purposes: []wrapping.Purpose{
			wrapping.Encrypt,
			wrapping.Decrypt,
		},
		Material: wrapping.KeyMaterial{
			RSAKey: rsa1,
		},
	}

	// Import the key
	name := fmt.Sprintf("test-%d", time.Now().Unix())
	version1, err := s.ImportKey(ctx, name, kmsKey)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if version1 == "" {
		t.Fatal("expected non-empty version")
	}
	t.Cleanup(func() {
		if exists, err := s.DeleteKey(ctx, name); exists && err != nil {
			t.Fatalf("failed to clean up key %q", name)
		}
	})

	// Get the public key for version 1 from Azure key vault and assert
	// it matches the public key that was generated and imported.
	kb, err := s.client.GetKey(ctx, s.buildBaseURL(), name, version1)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	testAssertPublicKeysMatch(t, kb.Key, rsa1.PublicKey)

	// Generate an additional RSA key to use for rotation.
	// We can reuse the KMSKey by swapping in the new material.
	rsa2 := testGenerateRSAKey(t)
	kmsKey.Material.RSAKey = rsa2

	// Rotate the key
	version2, err := s.RotateKey(ctx, name, kmsKey)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if version2 == "" {
		t.Fatal("expected non-empty version")
	}

	// Get the public key for version 2 from Azure key vault and assert
	// it matches the public key that was provided for the rotation.
	kb, err = s.client.GetKey(ctx, s.buildBaseURL(), name, version2)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	testAssertPublicKeysMatch(t, kb.Key, rsa2.PublicKey)

	// Expect that both versions of the key can be disabled
	for _, v := range []string{version1, version2} {
		if err = s.DisableKeyVersion(ctx, name, v); err != nil {
			t.Fatalf("err: %s", err.Error())
		}
		kb, err := s.client.GetKey(ctx, s.buildBaseURL(), name, v)
		if err != nil {
			t.Fatalf("err: %s", err.Error())
		}
		if to.Bool(kb.Attributes.Enabled) {
			t.Fatalf("expected key version %q to be disabled", v)
		}
	}

	// Expect that both versions of the key can be enabled
	for _, v := range []string{version1, version2} {
		if err = s.EnableKeyVersion(ctx, name, v); err != nil {
			t.Fatalf("err: %s", err.Error())
		}
		kb, err := s.client.GetKey(ctx, s.buildBaseURL(), name, v)
		if err != nil {
			t.Fatalf("err: %s", err.Error())
		}
		if !to.Bool(kb.Attributes.Enabled) {
			t.Fatalf("expected key version %q to be enabled", v)
		}
	}

	// Delete the key
	exists, err := s.DeleteKey(ctx, name)
	if err != nil || !exists {
		t.Fatalf("err: %s", err.Error())
	}

	// Expect that the key no longer exists
	kb, err = s.client.GetKey(ctx, s.buildBaseURL(), name, "")
	if err == nil || kb.StatusCode != http.StatusNotFound {
		t.Fatal("expected key to be not found")
	}
}

func testGenerateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	return k
}

func testAssertPublicKeysMatch(t *testing.T, jwk *keyvault.JSONWebKey, pub rsa.PublicKey) {
	t.Helper()

	azureRSAPub, err := jwkToRSAPublicKey(jwk)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if pub.N.Cmp(azureRSAPub.N) != 0 {
		t.Fatalf("expected same RSA modulus")
	}
	if pub.E != azureRSAPub.E {
		t.Fatalf("expected same RSA public exponent")
	}
}
