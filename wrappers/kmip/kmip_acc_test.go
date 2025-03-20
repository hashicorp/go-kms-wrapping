// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"os"
	"reflect"
	"testing"
)

// This test executes real calls. The calls themselves should be free,
// but the KMS key used is generally not free.
//
// To run this test, the following env variables need to be set:
//   - KMS_ACC_TESTS_RSA_KEY_ID
//   - KMS_ACC_TESTS_AES_KEY_ID
//   - BAO_KMIP_ENDPOINT
//   - BAO_KMIP_CLIENT_CERT
//   - BAO_KMIP_CLIENT_KEY
//   - BAO_KMIP_CA_CERT (optional)
//   - BAO_KMIP_SERVER_NAME (optional)
//   - BAO_KMIP_TLS12_CIPHERS (optional)
func TestAcckmipWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}
	tcs := []struct {
		keyId string
		alg   []string
	}{
		{"KMS_ACC_TESTS_AES_KEY_ID", []string{"AES_GCM"}},
		{"KMS_ACC_TESTS_RSA_KEY_ID", []string{"RSA_OAEP_SHA256", "RSA_OAEP_SHA384", "RSA_OAEP_SHA512"}},
	}
	for _, tc := range tcs {
		for _, alg := range tc.alg {
			t.Run(alg, func(t *testing.T) {
				keyId := os.Getenv(tc.keyId)
				if keyId == "" {
					t.SkipNow()
				}
				os.Setenv(EnvKmipEncryptAlg, alg)
				os.Setenv(EnvKmipWrapperKeyId, keyId)
				s := NewWrapper()
				_, err := s.SetConfig(context.Background())
				if err != nil {
					t.Fatalf("err : %s", err)
				}

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
			})
		}
	}
}
