// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	key_manager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
)

func testWrapper(t *testing.T) (*Wrapper, context.Context) {
	t.Helper()
	w := NewWrapper()
	w.client = &mockKeyManager{}
	w.region = "fr-par"
	w.keyId = "test-key-id"
	w.currentKeyId.Store(w.keyId)
	return w, context.Background()
}

func TestWrapperDirectEncryptDecrypt(t *testing.T) {
	w, ctx := testWrapper(t)
	plaintext := []byte("vault-master-key-material")

	blob, err := w.Encrypt(ctx, plaintext, wrapping.WithoutEnvelope(true))
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
}

func TestWrapperEnvelopeEncryptDecrypt(t *testing.T) {
	w, ctx := testWrapper(t)
	plaintext := []byte("vault-master-key-material-envelope")

	blob, err := w.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if blob.KeyInfo.Mechanism != ScalewayKmsEnvelopeAesGcmEncrypt {
		t.Fatalf("expected envelope mechanism, got %d", blob.KeyInfo.Mechanism)
	}

	got, err := w.Decrypt(ctx, blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(got) != string(plaintext) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plaintext)
	}
}

func TestWrapperSetConfigFromConfigMap(t *testing.T) {
	ctx := context.Background()
	w := NewWrapper()
	w.client = &mockKeyManager{}

	cfg, err := w.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		"disallow_env_vars": "true",
		"key_id":            "test-key-id",
		"region":            "fr-par",
		"project_id":        "test-project",
	}))
	if err != nil {
		t.Fatalf("set config: %v", err)
	}

	if cfg.Metadata["key_id"] != "test-key-id" {
		t.Fatalf("unexpected key_id metadata: %v", cfg.Metadata["key_id"])
	}
	if cfg.Metadata["region"] != "fr-par" {
		t.Fatalf("unexpected region metadata: %v", cfg.Metadata["region"])
	}

	typ, err := w.Type(ctx)
	if err != nil {
		t.Fatalf("type: %v", err)
	}
	if typ != wrapping.WrapperTypeScalewayKms {
		t.Fatalf("unexpected type: %s", typ)
	}
}

func TestWrapperSetConfigMissingKey(t *testing.T) {
	w := NewWrapper()
	w.client = &mockKeyManager{}

	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"disallow_env_vars": "true",
		"region":            "fr-par",
	}))
	if err == nil {
		t.Fatal("expected error for missing key_id")
	}
}

func TestWrapperSetConfigMissingRegion(t *testing.T) {
	w := NewWrapper()
	w.client = &mockKeyManager{}

	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"disallow_env_vars": "true",
		"key_id":            "test-key-id",
	}))
	if err == nil {
		t.Fatal("expected error for missing region")
	}
}

func TestWrapperSetConfigRejectsAsymmetricKey(t *testing.T) {
	w := NewWrapper()
	w.client = &mockKeyManager{
		getKey: func(_ *key_manager.GetKeyRequest) (*key_manager.Key, error) {
			return &key_manager.Key{
				ID:    "test-key-id",
				State: key_manager.KeyStateEnabled,
				Usage: &key_manager.KeyUsage{},
			}, nil
		},
	}

	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"disallow_env_vars": "true",
		"key_id":            "test-key-id",
		"region":            "fr-par",
	}))
	if err == nil {
		t.Fatal("expected error for non-symmetric key")
	}
}

func TestWrapperSetConfigRejectsDisabledKey(t *testing.T) {
	w := NewWrapper()
	w.client = &mockKeyManager{
		getKey: func(_ *key_manager.GetKeyRequest) (*key_manager.Key, error) {
			usage := key_manager.KeyAlgorithmSymmetricEncryptionAes256Gcm
			return &key_manager.Key{
				ID:    "test-key-id",
				State: key_manager.KeyStateDisabled,
				Usage: &key_manager.KeyUsage{
					SymmetricEncryption: &usage,
				},
			}, nil
		},
	}

	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"disallow_env_vars": "true",
		"key_id":            "test-key-id",
		"region":            "fr-par",
	}))
	if err == nil {
		t.Fatal("expected error for disabled key")
	}
}

func TestWrapperEncryptNilPlaintext(t *testing.T) {
	w, ctx := testWrapper(t)

	_, err := w.Encrypt(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil plaintext")
	}
}

func TestWrapperEncryptClientError(t *testing.T) {
	w, ctx := testWrapper(t)
	w.client = &mockKeyManager{
		encrypt: func(_ *key_manager.EncryptRequest) (*key_manager.EncryptResponse, error) {
			return nil, errors.New("kms unavailable")
		},
	}

	_, err := w.Encrypt(ctx, []byte("data"), wrapping.WithoutEnvelope(true))
	if err == nil {
		t.Fatal("expected encrypt error")
	}
}

func TestWrapperDecryptNilBlob(t *testing.T) {
	w, ctx := testWrapper(t)

	_, err := w.Decrypt(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil blob")
	}
}

func TestWrapperDecryptNilKeyInfo(t *testing.T) {
	w, ctx := testWrapper(t)

	_, err := w.Decrypt(ctx, &wrapping.BlobInfo{})
	if err == nil {
		t.Fatal("expected error for nil key info")
	}
}

func TestWrapperDecryptInvalidMechanism(t *testing.T) {
	w, ctx := testWrapper(t)

	_, err := w.Decrypt(ctx, &wrapping.BlobInfo{
		KeyInfo: &wrapping.KeyInfo{Mechanism: 99},
	})
	if err == nil {
		t.Fatal("expected error for invalid mechanism")
	}
}

func TestWrapperDecryptClientError(t *testing.T) {
	w, ctx := testWrapper(t)
	w.client = &mockKeyManager{
		decrypt: func(_ *key_manager.DecryptRequest) (*key_manager.DecryptResponse, error) {
			return nil, errors.New("kms unavailable")
		},
	}

	_, err := w.Decrypt(ctx, &wrapping.BlobInfo{
		Ciphertext: []byte("enc:data"),
		KeyInfo: &wrapping.KeyInfo{
			Mechanism: ScalewayKmsEncrypt,
			KeyId:     w.keyId,
		},
	})
	if err == nil {
		t.Fatal("expected decrypt error")
	}
}

func TestWrapperDecryptUsesBlobKeyId(t *testing.T) {
	w, ctx := testWrapper(t)
	blobKeyId := "blob-key-id"
	var gotKeyId string
	w.client = &mockKeyManager{
		decrypt: func(req *key_manager.DecryptRequest) (*key_manager.DecryptResponse, error) {
			gotKeyId = req.KeyID
			return &key_manager.DecryptResponse{Plaintext: []byte("ok")}, nil
		},
	}

	_, err := w.Decrypt(ctx, &wrapping.BlobInfo{
		Ciphertext: []byte("data"),
		KeyInfo: &wrapping.KeyInfo{
			Mechanism: ScalewayKmsEncrypt,
			KeyId:     blobKeyId,
		},
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if gotKeyId != blobKeyId {
		t.Fatalf("expected decrypt key_id %q, got %q", blobKeyId, gotKeyId)
	}
}

func TestWrapperKeyIdAfterEncrypt(t *testing.T) {
	w, ctx := testWrapper(t)
	respKeyId := "rotated-key-id"
	w.client = &mockKeyManager{
		encrypt: func(req *key_manager.EncryptRequest) (*key_manager.EncryptResponse, error) {
			return &key_manager.EncryptResponse{
				KeyID:      respKeyId,
				Ciphertext: req.Plaintext,
			}, nil
		},
	}

	_, err := w.Encrypt(ctx, []byte("data"), wrapping.WithoutEnvelope(true))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	id, err := w.KeyId(ctx)
	if err != nil {
		t.Fatalf("key id: %v", err)
	}
	if id != respKeyId {
		t.Fatalf("expected key id %q, got %q", respKeyId, id)
	}
}

func TestWrapperEncryptPassesContext(t *testing.T) {
	mock := &mockKeyManager{}
	w, ctx := testWrapper(t)
	w.client = mock

	_, err := w.Encrypt(ctx, []byte("data"), wrapping.WithoutEnvelope(true))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(mock.lastOpts) == 0 {
		t.Fatal("expected request options with context")
	}
}

func TestWrapperDecryptPassesContext(t *testing.T) {
	mock := &mockKeyManager{}
	w, ctx := testWrapper(t)
	w.client = mock

	_, err := w.Decrypt(ctx, &wrapping.BlobInfo{
		Ciphertext: []byte("enc:data"),
		KeyInfo: &wrapping.KeyInfo{
			Mechanism: ScalewayKmsEncrypt,
			KeyId:     w.keyId,
		},
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(mock.lastOpts) == 0 {
		t.Fatal("expected request options with context")
	}
}

func TestWrapperSetConfigPassesContext(t *testing.T) {
	mock := &mockKeyManager{}
	w := NewWrapper()
	w.client = mock

	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"disallow_env_vars": "true",
		"key_id":            "test-key-id",
		"region":            "fr-par",
		"access_key":        "SCWTESTACCESSKEY01",
		"secret_key":        "11111111-1111-1111-1111-111111111111",
	}))
	if err != nil {
		t.Fatalf("set config: %v", err)
	}
	if len(mock.lastOpts) == 0 {
		t.Fatal("expected request options with context on GetKey")
	}
}

func TestWrapperEncryptDirectModeOversizePlaintext(t *testing.T) {
	w, ctx := testWrapper(t)
	plaintext := make([]byte, maxDirectPlaintextSize+1)

	_, err := w.Encrypt(ctx, plaintext, wrapping.WithoutEnvelope(true))
	if err == nil {
		t.Fatal("expected error for oversize direct-mode plaintext")
	}
}

func TestWrapperSetConfigCredentialsFileIgnoresEnvAccessKeys(t *testing.T) {
	t.Setenv(EnvScalewayAccessKey, "SCWENVACCESSKEY01")
	t.Setenv(EnvScalewaySecretKey, "11111111-1111-1111-1111-111111111111")

	dir := t.TempDir()
	credentialsPath := filepath.Join(dir, "scaleway.yaml")
	if err := os.WriteFile(credentialsPath, []byte(`access_key: SCWFILEACCESSKEY01
secret_key: 22222222-2222-2222-2222-222222222222
`), 0o600); err != nil {
		t.Fatalf("write credentials file: %v", err)
	}

	w := NewWrapper()
	w.client = &mockKeyManager{}

	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"key_id":           "test-key-id",
		"region":           "fr-par",
		"credentials_file": credentialsPath,
	}))
	if err != nil {
		t.Fatalf("set config: %v", err)
	}
	if w.accessKey != "" || w.secretKey != "" {
		t.Fatalf("expected empty access/secret keys when credentials_file is set, got access=%q secret=%q", w.accessKey, w.secretKey)
	}
}

func TestWrapperSetConfigEnvOverridesConfigKeyId(t *testing.T) {
	t.Setenv(EnvScalewayKmsWrapperKeyId, "env-key-id")
	t.Setenv(EnvScalewayRegion, "nl-ams")

	w := NewWrapper()
	w.client = &mockKeyManager{}

	cfg, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"key_id":     "config-key-id",
		"region":     "fr-par",
		"access_key": "SCWTESTACCESSKEY01",
		"secret_key": "11111111-1111-1111-1111-111111111111",
	}))
	if err != nil {
		t.Fatalf("set config: %v", err)
	}
	if cfg.Metadata["key_id"] != "env-key-id" {
		t.Fatalf("expected env key_id, got %q", cfg.Metadata["key_id"])
	}
	if cfg.Metadata["region"] != "nl-ams" {
		t.Fatalf("expected env region, got %q", cfg.Metadata["region"])
	}
}

func TestWrapperSetConfigDisallowEnvVarsUsesConfig(t *testing.T) {
	t.Setenv(EnvScalewayKmsWrapperKeyId, "env-key-id")
	t.Setenv(EnvScalewayRegion, "nl-ams")

	w := NewWrapper()
	w.client = &mockKeyManager{}

	cfg, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"disallow_env_vars": "true",
		"key_id":            "config-key-id",
		"region":            "fr-par",
		"access_key":        "SCWTESTACCESSKEY01",
		"secret_key":        "11111111-1111-1111-1111-111111111111",
	}))
	if err != nil {
		t.Fatalf("set config: %v", err)
	}
	if cfg.Metadata["key_id"] != "config-key-id" {
		t.Fatalf("expected config key_id when env disallowed, got %q", cfg.Metadata["key_id"])
	}
	if cfg.Metadata["region"] != "fr-par" {
		t.Fatalf("expected config region when env disallowed, got %q", cfg.Metadata["region"])
	}
}

func TestWrapperAADRoundtrip(t *testing.T) {
	w, ctx := testWrapper(t)
	aad := []byte("associated-data")
	plaintext := []byte("vault-master-key-with-aad")

	blob, err := w.Encrypt(ctx, plaintext, wrapping.WithAad(aad))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := w.Decrypt(ctx, blob, wrapping.WithAad(aad))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plaintext)
	}
}
