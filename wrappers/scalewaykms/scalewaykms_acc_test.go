// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

import (
	"context"
	"os"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// This test executes real calls against Scaleway Key Manager.
//
// To run this test, set VAULT_ACC=1 or KMS_ACC_TESTS=1 and configure:
//   - SCALEWAYKMS_WRAPPER_KEY_ID or VAULT_SCALEWAYKMS_SEAL_KEY_ID
//   - SCW_DEFAULT_REGION
//   - SCW_ACCESS_KEY and SCW_SECRET_KEY (or credentials via Scaleway config)
func TestAccScalewayKMSWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	keyId := os.Getenv(EnvScalewayKmsWrapperKeyId)
	if keyId == "" {
		keyId = os.Getenv(EnvVaultScalewayKmsSealKeyId)
	}
	region := os.Getenv(EnvScalewayRegion)
	if keyId == "" || region == "" {
		t.Skip("SCALEWAYKMS_WRAPPER_KEY_ID (or VAULT_SCALEWAYKMS_SEAL_KEY_ID) and SCW_DEFAULT_REGION must be set")
	}

	ctx := context.Background()
	w := NewWrapper()

	_, err := w.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		"key_id": keyId,
		"region": region,
	}))
	if err != nil {
		t.Fatalf("set config: %v", err)
	}

	plaintext := []byte("go-kms-wrapping-scaleway-acc-test")

	for name, withoutEnvelope := range map[string]bool{
		"direct":   true,
		"envelope": false,
	} {
		t.Run(name, func(t *testing.T) {
			var opts []wrapping.Option
			if withoutEnvelope {
				opts = append(opts, wrapping.WithoutEnvelope(true))
			}

			blob, err := w.Encrypt(ctx, plaintext, opts...)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			got, err := w.Decrypt(ctx, blob)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			if string(got) != string(plaintext) {
				t.Fatalf("roundtrip mismatch: got %q want %q", got, plaintext)
			}
		})
	}
}
