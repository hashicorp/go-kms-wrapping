// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testTransitClient struct {
	keyID string
	wrap  wrapping.Wrapper
}

func newTestTransitClient(keyID string) *testTransitClient {
	return &testTransitClient{
		keyID: keyID,
		wrap:  wrapping.NewTestWrapper(nil),
	}
}

func (m *testTransitClient) Close() {}

func (m *testTransitClient) Encrypt(plaintext []byte) ([]byte, error) {
	v, err := m.wrap.Encrypt(context.Background(), plaintext, nil)
	if err != nil {
		return nil, err
	}

	return []byte(fmt.Sprintf("v1:%s:%s", m.keyID, string(v.Ciphertext))), nil
}

func (m *testTransitClient) Decrypt(ciphertext []byte) ([]byte, error) {
	splitKey := strings.Split(string(ciphertext), ":")
	if len(splitKey) != 3 {
		return nil, errors.New("invalid ciphertext returned")
	}

	data := &wrapping.BlobInfo{
		Ciphertext: []byte(splitKey[2]),
	}
	v, err := m.wrap.Decrypt(context.Background(), data, nil)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func TestTransitWrapper_Lifecycle(t *testing.T) {
	s := NewWrapper()

	keyId := "test-key"
	s.client = newTestTransitClient(keyId)

	// Test Encrypt and Decrypt calls
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

	kid, err := s.KeyId(context.Background())
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if kid != keyId {
		t.Fatalf("key id does not match: expected %s, got %s", keyId, kid)
	}
}

func TestSetConfig(t *testing.T) {
	const (
		testWithMountPath      = "transit/"
		testWithAddress        = "http://localhost:8200"
		testWithKeyName        = "example-key"
		testWithDisableRenewal = "true"
		testWithNamespace      = "ns1/"
		testWithToken          = "vault-plaintext-root-token"

		envVaultNamespace = "VAULT_NAMESPACE"
	)

	tests := []struct {
		name            string
		opts            []wrapping.Option
		setup           func(t *testing.T)
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "missing-mount",
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken("vault-plaintext-root-token"),
				WithKeyName("example-key"),
				WithNamespace("ns1/"),
			},
			wantErr:         true,
			wantErrContains: "mount_path is required",
		},
		{
			name: "success-with-env-mount",
			setup: func(t *testing.T) {
				require.NoError(t, os.Setenv(EnvTransitWrapperMountPath, testWithMountPath))
				t.Cleanup(func() { os.Unsetenv(EnvTransitWrapperMountPath) })
			},
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithKeyName(testWithKeyName),
				WithNamespace(testWithNamespace),
			},
		},
		{
			name: "success-with-env-mount-seal",
			setup: func(t *testing.T) {
				require.NoError(t, os.Setenv(EnvVaultTransitSealMountPath, testWithMountPath))
				t.Cleanup(func() { os.Unsetenv(EnvVaultTransitSealMountPath) })
			},
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithKeyName(testWithKeyName),
				WithNamespace(testWithNamespace),
			},
		},
		{
			name: "missing-key-name",
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithNamespace(testWithNamespace),
			},
			wantErr:         true,
			wantErrContains: "key_name is required",
		},
		{
			name: "success-with-env-key-name",
			setup: func(t *testing.T) {
				require.NoError(t, os.Setenv(EnvTransitWrapperKeyName, testWithKeyName))
				t.Cleanup(func() { os.Unsetenv(EnvTransitWrapperKeyName) })
			},
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithNamespace(testWithNamespace)},
		},
		{
			name: "success-with-env-key-name-seal",
			setup: func(t *testing.T) {
				require.NoError(t, os.Setenv(EnvVaultTransitSealKeyName, testWithKeyName))
				t.Cleanup(func() { os.Unsetenv(EnvVaultTransitSealKeyName) })
			},
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithNamespace(testWithNamespace),
			},
		},
		{
			name: "success-with-env-disable-renewal",
			setup: func(t *testing.T) {
				require.NoError(t, os.Setenv(EnvTransitWrapperDisableRenewal, testWithDisableRenewal))
				t.Cleanup(func() { os.Unsetenv(EnvTransitWrapperDisableRenewal) })
			},
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithKeyName(testWithKeyName),
				WithNamespace(testWithNamespace),
			},
		},
		{
			name: "success-with-env-disable-renewal-seal",
			setup: func(t *testing.T) {
				require.NoError(t, os.Setenv(EnvVaultTransitSealDisableRenewal, testWithDisableRenewal))
				t.Cleanup(func() { os.Unsetenv(EnvVaultTransitSealDisableRenewal) })
			},
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithKeyName(testWithKeyName),
				WithNamespace(testWithNamespace),
			},
		},
		{
			name: "error-invalid-env-disable-renewal",
			setup: func(t *testing.T) {
				require.NoError(t, os.Setenv(EnvTransitWrapperDisableRenewal, "invalid-disable-renewal"))
				t.Cleanup(func() { os.Unsetenv(EnvTransitWrapperDisableRenewal) })
			},
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithKeyName(testWithKeyName),
				WithNamespace(testWithNamespace),
			},
			wantErr:         true,
			wantErrContains: "parsing \"invalid-disable-renewal\": invalid syntax",
		},
		{
			name: "success-with-disable-renewal",
			opts: []wrapping.Option{
				WithDisableRenewal(testWithDisableRenewal),
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithKeyName(testWithKeyName),
				WithNamespace(testWithNamespace),
			},
		},
		{
			name: "success-with-env-namespace",
			setup: func(t *testing.T) {
				require.NoError(t, os.Setenv(envVaultNamespace, testWithNamespace))
				t.Cleanup(func() { os.Unsetenv(envVaultNamespace) })
			},
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithKeyName(testWithKeyName),
			},
		},
		{
			name: "error-SetConfig-bad-scheme",
			opts: []wrapping.Option{
				WithAddress("bad-scheme"),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithKeyName(testWithKeyName),
				WithNamespace(testWithNamespace),
			},
			wantErr:         true,
			wantErrContains: "unsupported protocol scheme",
		},
		{
			name: "error-bad-address",
			opts: []wrapping.Option{
				WithAddress(" https://bad-address"),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithKeyName(testWithKeyName),
				WithNamespace(testWithNamespace),
			},
			wantErr:         true,
			wantErrContains: "first path segment in URL cannot contain colon",
		},
		{
			name: "error-perm-denied",
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				// WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithKeyName(testWithKeyName),
				WithNamespace(testWithNamespace),
			},
			wantErr:         true,
			wantErrContains: "permission denied",
		},
		{
			name: "success-with-opts",
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithKeyName(testWithKeyName),
				WithNamespace(testWithNamespace),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tc.setup != nil {
				tc.setup(t)
			}
			w := NewWrapper()
			_, err := w.SetConfig(context.Background(), tc.opts...)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			testPt := []byte("test-plaintext")
			blob, err := w.Encrypt(context.Background(), testPt)
			require.NoError(err)
			pt, err := w.Decrypt(context.Background(), blob)
			require.NoError(err)
			assert.Equal(testPt, pt)

			transitClient, ok := w.client.(*TransitClient)
			require.True(ok)
			assert.NotNil(transitClient.GetApiClient())
			assert.NotEmpty(transitClient.GetMountPath())

			w.client.Close()
			t.Log(pt)
		})
	}
}
