// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package tencentcloudkms

import (
	"context"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
)

// newTestWrapper returns a wrapper with a mocked KMS client so that SetConfig
// does not attempt any network access.
func newTestWrapper() *Wrapper {
	w := NewWrapper()
	w.client = &mockTencentCloudKmsWrapperClient{
		keyID: common.StringPtr(tencentCloudTestKeyID),
	}
	return w
}

// baseOpts are the options required for SetConfig to succeed, on top of which
// each test layers the role settings it cares about.
func baseOpts(extra ...wrapping.Option) []wrapping.Option {
	opts := []wrapping.Option{
		wrapping.WithKeyId(tencentCloudTestKeyID),
		wrapping.WithDisallowEnvVars(true),
		WithAccessKey("test-access-key"),
		WithSecretKey("test-secret-key"),
	}
	return append(opts, extra...)
}

// TestParseRoleDurationSeconds covers the client side validation of the
// role_duration_seconds value.
func TestParseRoleDurationSeconds(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    uint64
		wantErr bool
	}{
		{"min accepted", "900", 900, false},
		{"max accepted", "43200", 43200, false},
		{"mid range", "7200", 7200, false},
		{"zero means unset", "0", 0, false},
		{"below minimum", "899", 0, true},
		{"above maximum", "43201", 0, true},
		{"not a number", "abc", 0, true},
		{"negative", "-1", 0, true},
		{"empty", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRoleDurationSeconds(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseRoleDurationSeconds(%q): expected error, got none", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRoleDurationSeconds(%q): unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("parseRoleDurationSeconds(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// TestRoleConfigFromConfigMap verifies that all role settings can be supplied
// through WithConfigMap, which is how Vault passes its seal stanza.
func TestRoleConfigFromConfigMap(t *testing.T) {
	const (
		wantArn      = "qcs::cam::uin/100000002:roleName/CrossAccountKMSRole"
		wantSession  = "vault-seal"
		wantExternal = "shared-secret"
	)

	w := newTestWrapper()
	if _, err := w.SetConfig(context.Background(), baseOpts(
		wrapping.WithConfigMap(map[string]string{
			"role_arn":              wantArn,
			"role_session_name":     wantSession,
			"role_external_id":      wantExternal,
			"role_duration_seconds": "43200",
		}),
	)...); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	if w.roleArn != wantArn {
		t.Errorf("roleArn = %q, want %q", w.roleArn, wantArn)
	}
	if w.roleSessionName != wantSession {
		t.Errorf("roleSessionName = %q, want %q", w.roleSessionName, wantSession)
	}
	if w.roleExternalId != wantExternal {
		t.Errorf("roleExternalId = %q, want %q", w.roleExternalId, wantExternal)
	}
	if w.roleDurationSeconds != 43200 {
		t.Errorf("roleDurationSeconds = %d, want 43200", w.roleDurationSeconds)
	}
}

// TestRoleConfigFromOptionFuncs verifies the exported With* helpers.
func TestRoleConfigFromOptionFuncs(t *testing.T) {
	const wantArn = "qcs::cam::uin/100000001:roleName/LocalRole"

	w := newTestWrapper()
	if _, err := w.SetConfig(context.Background(), baseOpts(
		WithRoleArn(wantArn),
		WithRoleSessionName("from-option"),
		WithRoleExternalId("ext-id"),
		WithRoleDurationSeconds(3600),
	)...); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	if w.roleArn != wantArn {
		t.Errorf("roleArn = %q, want %q", w.roleArn, wantArn)
	}
	if w.roleSessionName != "from-option" {
		t.Errorf("roleSessionName = %q, want %q", w.roleSessionName, "from-option")
	}
	if w.roleExternalId != "ext-id" {
		t.Errorf("roleExternalId = %q, want %q", w.roleExternalId, "ext-id")
	}
	if w.roleDurationSeconds != 3600 {
		t.Errorf("roleDurationSeconds = %d, want 3600", w.roleDurationSeconds)
	}
}

// TestWithRoleDurationSecondsValidation ensures the option function rejects
// out-of-range values instead of deferring the failure to the STS call.
func TestWithRoleDurationSecondsValidation(t *testing.T) {
	for _, d := range []uint64{1, 899, 43201, 100000} {
		w := newTestWrapper()
		_, err := w.SetConfig(context.Background(), baseOpts(WithRoleDurationSeconds(d))...)
		if err == nil {
			t.Errorf("WithRoleDurationSeconds(%d): expected error, got none", d)
		}
	}

	// 0 means "unset" and must be accepted.
	w := newTestWrapper()
	if _, err := w.SetConfig(context.Background(), baseOpts(WithRoleDurationSeconds(0))...); err != nil {
		t.Errorf("WithRoleDurationSeconds(0): unexpected error: %v", err)
	}
}

// TestInvalidRoleDurationInConfigMap ensures a bad config map value surfaces as
// a SetConfig error.
func TestInvalidRoleDurationInConfigMap(t *testing.T) {
	w := newTestWrapper()
	_, err := w.SetConfig(context.Background(), baseOpts(
		wrapping.WithConfigMap(map[string]string{"role_duration_seconds": "not-a-number"}),
	)...)
	if err == nil {
		t.Fatal("expected SetConfig to fail for an invalid role_duration_seconds")
	}
}

// TestRoleEnvVars verifies that the role settings are picked up from the
// environment when env vars are allowed.
func TestRoleEnvVars(t *testing.T) {
	t.Setenv(PROVIDER_ROLE_ARN, "qcs::cam::uin/100000003:roleName/FromEnv")
	t.Setenv(PROVIDER_ROLE_SESSION_NM, "env-session")
	t.Setenv(PROVIDER_ROLE_EXTERN_ID, "env-external-id")
	t.Setenv(PROVIDER_ROLE_DURATION, "1800")

	w := newTestWrapper()
	if _, err := w.SetConfig(context.Background(),
		wrapping.WithKeyId(tencentCloudTestKeyID),
		WithAccessKey("test-access-key"),
		WithSecretKey("test-secret-key"),
	); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	if w.roleArn != "qcs::cam::uin/100000003:roleName/FromEnv" {
		t.Errorf("roleArn = %q, want value from env", w.roleArn)
	}
	if w.roleSessionName != "env-session" {
		t.Errorf("roleSessionName = %q, want %q", w.roleSessionName, "env-session")
	}
	if w.roleExternalId != "env-external-id" {
		t.Errorf("roleExternalId = %q, want %q", w.roleExternalId, "env-external-id")
	}
	if w.roleDurationSeconds != 1800 {
		t.Errorf("roleDurationSeconds = %d, want 1800", w.roleDurationSeconds)
	}
}

// TestRoleEnvVarsDisallowed verifies that WithDisallowEnvVars (which is what
// Vault passes) prevents the environment from being consulted, while values
// supplied through the config map still take effect.
func TestRoleEnvVarsDisallowed(t *testing.T) {
	t.Setenv(PROVIDER_ROLE_ARN, "qcs::cam::uin/100000003:roleName/FromEnv")
	t.Setenv(PROVIDER_ROLE_DURATION, "1800")

	// Environment must be ignored entirely.
	w := newTestWrapper()
	if _, err := w.SetConfig(context.Background(), baseOpts()...); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if w.roleArn != "" {
		t.Errorf("roleArn = %q, want empty (env vars disallowed)", w.roleArn)
	}
	if w.roleDurationSeconds != 0 {
		t.Errorf("roleDurationSeconds = %d, want 0 (env vars disallowed)", w.roleDurationSeconds)
	}

	// The config map must still win, since that is how Vault forwards the
	// values it resolved itself.
	const wantArn = "qcs::cam::uin/100000004:roleName/FromConfig"
	w2 := newTestWrapper()
	if _, err := w2.SetConfig(context.Background(), baseOpts(
		wrapping.WithConfigMap(map[string]string{
			"role_arn":              wantArn,
			"role_duration_seconds": "900",
		}),
	)...); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if w2.roleArn != wantArn {
		t.Errorf("roleArn = %q, want %q", w2.roleArn, wantArn)
	}
	if w2.roleDurationSeconds != 900 {
		t.Errorf("roleDurationSeconds = %d, want 900", w2.roleDurationSeconds)
	}
}

// TestCredentialEnvVarsDisallowed covers the non-role settings, which had the
// same env var precedence problem.
func TestCredentialEnvVarsDisallowed(t *testing.T) {
	t.Setenv(PROVIDER_KMS_KEY_ID, "key-from-env")
	t.Setenv(PROVIDER_REGION, "ap-shanghai")
	t.Setenv(PROVIDER_SECRET_ID, "ak-from-env")
	t.Setenv(PROVIDER_SECRET_KEY, "sk-from-env")
	t.Setenv(PROVIDER_SECURITY_TOKEN, "token-from-env")

	w := newTestWrapper()
	if _, err := w.SetConfig(context.Background(),
		wrapping.WithKeyId(tencentCloudTestKeyID),
		wrapping.WithDisallowEnvVars(true),
		WithRegion("ap-guangzhou"),
		WithAccessKey("ak-from-config"),
		WithSecretKey("sk-from-config"),
	); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	if w.keyId != tencentCloudTestKeyID {
		t.Errorf("keyId = %q, want %q", w.keyId, tencentCloudTestKeyID)
	}
	if w.region != "ap-guangzhou" {
		t.Errorf("region = %q, want %q", w.region, "ap-guangzhou")
	}
	if w.accessKey != "ak-from-config" {
		t.Errorf("accessKey = %q, want %q", w.accessKey, "ak-from-config")
	}
	if w.secretKey != "sk-from-config" {
		t.Errorf("secretKey = %q, want %q", w.secretKey, "sk-from-config")
	}
	if w.sessionToken != "" {
		t.Errorf("sessionToken = %q, want empty (env vars disallowed)", w.sessionToken)
	}
}

// TestBuildAssumeRoleRequest verifies how the wrapper configuration is
// translated into STS AssumeRole parameters.
func TestBuildAssumeRoleRequest(t *testing.T) {
	t.Run("defaults session name and omits optional fields", func(t *testing.T) {
		w := NewWrapper()
		w.roleArn = "qcs::cam::uin/1:roleName/R"

		req := w.buildAssumeRoleRequest()

		if req.RoleArn == nil || *req.RoleArn != w.roleArn {
			t.Errorf("RoleArn = %v, want %q", req.RoleArn, w.roleArn)
		}
		if req.RoleSessionName == nil || *req.RoleSessionName != defaultRoleSessionName {
			t.Errorf("RoleSessionName = %v, want %q", req.RoleSessionName, defaultRoleSessionName)
		}
		if req.ExternalId != nil {
			t.Errorf("ExternalId = %v, want nil when unset", *req.ExternalId)
		}
		if req.DurationSeconds != nil {
			t.Errorf("DurationSeconds = %v, want nil when unset", *req.DurationSeconds)
		}
	})

	t.Run("passes through all configured fields", func(t *testing.T) {
		w := NewWrapper()
		w.roleArn = "qcs::cam::uin/2:roleName/R2"
		w.roleSessionName = "my-session"
		w.roleExternalId = "my-external-id"
		w.roleDurationSeconds = 43200

		req := w.buildAssumeRoleRequest()

		if req.RoleSessionName == nil || *req.RoleSessionName != "my-session" {
			t.Errorf("RoleSessionName = %v, want %q", req.RoleSessionName, "my-session")
		}
		if req.ExternalId == nil || *req.ExternalId != "my-external-id" {
			t.Errorf("ExternalId = %v, want %q", req.ExternalId, "my-external-id")
		}
		if req.DurationSeconds == nil || *req.DurationSeconds != 43200 {
			t.Errorf("DurationSeconds = %v, want 43200", req.DurationSeconds)
		}
	})
}

// TestEndpointConfig verifies the endpoint override can be supplied through the
// config map, the option function, and the environment.
func TestEndpointConfig(t *testing.T) {
	const wantEndpoint = "kms.tencentcloudapi.com"

	t.Run("from config map", func(t *testing.T) {
		w := newTestWrapper()
		info, err := w.SetConfig(context.Background(), baseOpts(
			wrapping.WithConfigMap(map[string]string{"endpoint": wantEndpoint}),
		)...)
		if err != nil {
			t.Fatalf("SetConfig: %v", err)
		}
		if w.endpoint != wantEndpoint {
			t.Errorf("endpoint = %q, want %q", w.endpoint, wantEndpoint)
		}
		if got := info.Metadata["endpoint"]; got != wantEndpoint {
			t.Errorf("metadata endpoint = %q, want %q", got, wantEndpoint)
		}
	})

	t.Run("from option func", func(t *testing.T) {
		w := newTestWrapper()
		if _, err := w.SetConfig(context.Background(), baseOpts(WithEndpoint(wantEndpoint))...); err != nil {
			t.Fatalf("SetConfig: %v", err)
		}
		if w.endpoint != wantEndpoint {
			t.Errorf("endpoint = %q, want %q", w.endpoint, wantEndpoint)
		}
	})

	t.Run("from env var", func(t *testing.T) {
		t.Setenv(PROVIDER_KMS_ENDPOINT, wantEndpoint)
		w := newTestWrapper()
		if _, err := w.SetConfig(context.Background(),
			wrapping.WithKeyId(tencentCloudTestKeyID),
			WithAccessKey("ak"), WithSecretKey("sk"),
		); err != nil {
			t.Fatalf("SetConfig: %v", err)
		}
		if w.endpoint != wantEndpoint {
			t.Errorf("endpoint = %q, want %q", w.endpoint, wantEndpoint)
		}
	})

	t.Run("env var ignored when disallowed", func(t *testing.T) {
		t.Setenv(PROVIDER_KMS_ENDPOINT, wantEndpoint)
		w := newTestWrapper()
		if _, err := w.SetConfig(context.Background(), baseOpts()...); err != nil {
			t.Fatalf("SetConfig: %v", err)
		}
		if w.endpoint != "" {
			t.Errorf("endpoint = %q, want empty (env vars disallowed)", w.endpoint)
		}
	})

	t.Run("omitted from metadata when unset", func(t *testing.T) {
		w := newTestWrapper()
		info, err := w.SetConfig(context.Background(), baseOpts()...)
		if err != nil {
			t.Fatalf("SetConfig: %v", err)
		}
		if _, ok := info.Metadata["endpoint"]; ok {
			t.Error("metadata should not contain an endpoint key when unset")
		}
	})
}

// TestNewClientProfile checks that the endpoint override only lands on the
// profile when one was requested. This matters because the STS client is built
// with an empty endpoint so that assuming a role is never redirected to the
// KMS endpoint.
func TestNewClientProfile(t *testing.T) {
	t.Run("without endpoint", func(t *testing.T) {
		cpf := newClientProfile("")
		if cpf.HttpProfile.Endpoint != "" {
			t.Errorf("Endpoint = %q, want empty", cpf.HttpProfile.Endpoint)
		}
		if cpf.HttpProfile.ReqMethod != "POST" {
			t.Errorf("ReqMethod = %q, want POST", cpf.HttpProfile.ReqMethod)
		}
	})

	t.Run("with endpoint", func(t *testing.T) {
		const ep = "kms.tencentcloudapi.com"
		cpf := newClientProfile(ep)
		if cpf.HttpProfile.Endpoint != ep {
			t.Errorf("Endpoint = %q, want %q", cpf.HttpProfile.Endpoint, ep)
		}
	})

	t.Run("profiles are independent", func(t *testing.T) {
		kmsProfile := newClientProfile("kms.tencentcloudapi.com")
		stsProfile := newClientProfile("")
		if stsProfile.HttpProfile.Endpoint != "" {
			t.Errorf("STS profile picked up the KMS endpoint: %q", stsProfile.HttpProfile.Endpoint)
		}
		if kmsProfile == stsProfile {
			t.Error("expected distinct profile instances")
		}
	})
}

// TestNoRoleConfigured is a regression guard: with no role settings the wrapper
// must behave exactly as before, i.e. never attempt an AssumeRole.
func TestNoRoleConfigured(t *testing.T) {
	w := newTestWrapper()
	if _, err := w.SetConfig(context.Background(), baseOpts()...); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	if w.roleArn != "" {
		t.Errorf("roleArn = %q, want empty", w.roleArn)
	}
	if w.accessKey != "test-access-key" {
		t.Errorf("accessKey = %q, want the configured value (not replaced by STS)", w.accessKey)
	}
	if w.sessionToken != "" {
		t.Errorf("sessionToken = %q, want empty (no AssumeRole performed)", w.sessionToken)
	}
}
