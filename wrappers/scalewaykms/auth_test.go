// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthClientOptionsFromCredentialsFile(t *testing.T) {
	dir := t.TempDir()
	credentialsPath := filepath.Join(dir, "scaleway.yaml")
	const (
		accessKey = "SCWTESTACCESSKEY01"
		secretKey = "11111111-1111-1111-1111-111111111111"
	)
	if err := os.WriteFile(credentialsPath, []byte(`access_key: `+accessKey+`
secret_key: `+secretKey+`
`), 0o600); err != nil {
		t.Fatalf("write credentials file: %v", err)
	}

	w := NewWrapper()
	w.disallowEnvVars = true
	w.credentialsFile = credentialsPath
	w.region = "fr-par"
	w.projectId = "22222222-2222-2222-2222-222222222222"

	opts, err := w.authClientOptions()
	if err != nil {
		t.Fatalf("authClientOptions: %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected 1 client option, got %d", len(opts))
	}
}

func TestAuthClientOptionsRequiresCredentialsWhenEnvDisabled(t *testing.T) {
	w := NewWrapper()
	w.disallowEnvVars = true
	w.region = "fr-par"
	w.keyId = "test-key"

	_, err := w.authClientOptions()
	if err == nil {
		t.Fatal("expected error when credentials are missing with disallow_env_vars=true")
	}
}

func TestAuthClientOptionsExplicitKeys(t *testing.T) {
	w := NewWrapper()
	w.disallowEnvVars = true
	w.accessKey = "SCWTESTACCESSKEY01"
	w.secretKey = "11111111-1111-1111-1111-111111111111"

	opts, err := w.authClientOptions()
	if err != nil {
		t.Fatalf("authClientOptions: %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected 1 client option, got %d", len(opts))
	}
}

func TestAuthClientOptionsMissingCredentialsFile(t *testing.T) {
	w := NewWrapper()
	w.disallowEnvVars = true
	w.credentialsFile = filepath.Join(t.TempDir(), "missing.yaml")

	_, err := w.authClientOptions()
	if err == nil {
		t.Fatal("expected error for missing credentials file")
	}
}

func TestAuthClientOptionsMalformedCredentialsFile(t *testing.T) {
	dir := t.TempDir()
	credentialsPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(credentialsPath, []byte("access_key: [\n"), 0o600); err != nil {
		t.Fatalf("write credentials file: %v", err)
	}

	w := NewWrapper()
	w.disallowEnvVars = true
	w.credentialsFile = credentialsPath

	_, err := w.authClientOptions()
	if err == nil {
		t.Fatal("expected error for malformed credentials file")
	}
}

func TestAuthClientOptionsMissingNamedProfile(t *testing.T) {
	dir := t.TempDir()
	credentialsPath := filepath.Join(dir, "scaleway.yaml")
	if err := os.WriteFile(credentialsPath, []byte(`access_key: SCWTESTACCESSKEY01
secret_key: 11111111-1111-1111-1111-111111111111
`), 0o600); err != nil {
		t.Fatalf("write credentials file: %v", err)
	}

	w := NewWrapper()
	w.disallowEnvVars = true
	w.credentialsFile = credentialsPath
	w.profile = "does-not-exist"

	_, err := w.authClientOptions()
	if err == nil {
		t.Fatal("expected error for missing profile")
	}
}

func TestAuthClientOptionsCredentialsFileOverExplicitKeys(t *testing.T) {
	dir := t.TempDir()
	credentialsPath := filepath.Join(dir, "scaleway.yaml")
	if err := os.WriteFile(credentialsPath, []byte(`access_key: SCWFILEACCESSKEY01
secret_key: 22222222-2222-2222-2222-222222222222
`), 0o600); err != nil {
		t.Fatalf("write credentials file: %v", err)
	}

	w := NewWrapper()
	w.credentialsFile = credentialsPath
	w.accessKey = "SCWWRONGACCESSKEY1"
	w.secretKey = "11111111-1111-1111-1111-111111111111"

	opts, err := w.authClientOptions()
	if err != nil {
		t.Fatalf("authClientOptions: %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected 1 client option, got %d", len(opts))
	}
}

func TestAuthClientOptionsProfileOnlyLoadConfigHint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SCW_CONFIG_PATH", filepath.Join(home, "nonexistent.yaml"))

	w := NewWrapper()
	w.disallowEnvVars = true
	w.profile = "default"

	_, err := w.loadAuthProfile()
	if err == nil {
		t.Fatal("expected error when default scw config is unavailable")
	}
	if !strings.Contains(err.Error(), "credentials_file") {
		t.Fatalf("expected credentials_file hint, got: %v", err)
	}
}
