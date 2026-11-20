// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package huaweicloudkms

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
)

const huaweiCloudTestKeyId = "foo"

func TestHuaweiCloudKmsWrapper(t *testing.T) {
	s := NewWrapper()
	s.client = &mockHuaweiCloudKmsWrapperClient{}

	if _, err := s.SetConfig(context.Background()); err == nil {
		t.Fatal("expected error when HuaweiCloudKmsWrapper key ID is not provided")
	}

	// Set the key
	t.Setenv(EnvHuaweiCloudKmsWrapperKeyId, huaweiCloudTestKeyId)
	if _, err := s.SetConfig(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Env vars must be ignored when disallowed
	if _, err := s.SetConfig(context.Background(), wrapping.WithDisallowEnvVars(true)); err == nil {
		t.Fatal("expected error when env vars are disallowed and no key id is configured")
	}
	cfg, err := s.SetConfig(context.Background(), wrapping.WithDisallowEnvVars(true), wrapping.WithKeyId("bar"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Metadata["kms_key_id"] != "bar" {
		t.Fatalf("expected key id bar, got %q", cfg.Metadata["kms_key_id"])
	}
}

func TestHuaweiCloudKmsWrapper_Lifecycle(t *testing.T) {
	s := NewWrapper()
	s.client = &mockHuaweiCloudKmsWrapperClient{}

	t.Setenv(EnvHuaweiCloudKmsWrapperKeyId, huaweiCloudTestKeyId)
	if _, err := s.SetConfig(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if swi.KeyInfo.Mechanism != HuaweiCloudKmsEnvelopeAesGcmEncrypt {
		t.Fatalf("unexpected mechanism %d", swi.KeyInfo.Mechanism)
	}

	pt, err := s.Decrypt(context.Background(), swi)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}

	swi, err = s.Encrypt(context.Background(), input, wrapping.WithoutEnvelope(true))
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if swi.KeyInfo.Mechanism != HuaweiCloudKmsEncrypt {
		t.Fatalf("unexpected mechanism %d", swi.KeyInfo.Mechanism)
	}

	pt, err = s.Decrypt(context.Background(), swi)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}

	if keyId, _ := s.KeyId(context.Background()); keyId != huaweiCloudTestKeyId {
		t.Fatalf("expected key id %q, got %q", huaweiCloudTestKeyId, keyId)
	}
}

func TestIsProjectId(t *testing.T) {
	for in, want := range map[string]bool{
		"":                                 false,
		"ap-southeast-3":                   false,
		"0d0466b0e7274d9cb35df84bb474a37f": true,
		"0d0466b0e7274d9cb35df84bb474a37g": false,
	} {
		if got := isProjectId(in); got != want {
			t.Errorf("isProjectId(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestHuaweiCloudKmsWrapper_SetConfigWithoutClient(t *testing.T) {
	// Without an injected client SetConfig must build one, so credentials
	// and region become required and an unknown region must fail cleanly.
	t.Setenv(EnvHuaweiCloudKmsWrapperKeyId, huaweiCloudTestKeyId)
	_, err := NewWrapper().SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"access_key": "ak",
		"secret_key": "sk",
	}))
	if err == nil || !strings.Contains(err.Error(), "'region' not found") {
		t.Fatalf("expected missing region error, got %v", err)
	}

	// No AK/SK falls back to the SDK provider chain, which must fail here
	// (no env, no profile, no metadata service) rather than panic.
	t.Setenv("HOME", t.TempDir())
	_, err = NewWrapper().SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"region": "tr-west-1",
	}))
	if err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("expected credential chain error, got %v", err)
	}

	_, err = NewWrapper().SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"region":     "no-such-region-1",
		"access_key": "ak",
		"secret_key": "sk",
	}))
	if err == nil || !strings.Contains(err.Error(), "no-such-region-1") {
		t.Fatalf("expected unknown region error, got %v", err)
	}
}

// mockHuaweiCloudKmsWrapperClient fakes KMS with base64: "ciphertext" is the
// base64 encoding of the plaintext string KMS was given.
type mockHuaweiCloudKmsWrapperClient struct{}

func (m *mockHuaweiCloudKmsWrapperClient) ListKeyDetail(request *model.ListKeyDetailRequest) (*model.ListKeyDetailResponse, error) {
	if request.Body == nil || request.Body.KeyId == "" {
		return nil, errors.New("key not found")
	}
	keyId := request.Body.KeyId
	return &model.ListKeyDetailResponse{KeyInfo: &model.KeyDetails{KeyId: &keyId}}, nil
}

func (m *mockHuaweiCloudKmsWrapperClient) EncryptData(request *model.EncryptDataRequest) (*model.EncryptDataResponse, error) {
	keyId := request.Body.KeyId
	ct := base64.StdEncoding.EncodeToString([]byte(request.Body.PlainText))
	return &model.EncryptDataResponse{KeyId: &keyId, CipherText: &ct}, nil
}

func (m *mockHuaweiCloudKmsWrapperClient) DecryptData(request *model.DecryptDataRequest) (*model.DecryptDataResponse, error) {
	decoded, err := base64.StdEncoding.DecodeString(request.Body.CipherText)
	if err != nil {
		return nil, err
	}
	pt := string(decoded)
	return &model.DecryptDataResponse{PlainText: &pt}, nil
}
