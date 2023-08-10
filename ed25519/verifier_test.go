// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ed25519

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewVerifier(t *testing.T) {
	t.Parallel()
	const (
		testKeyId      = "key-id"
		testKeyPurpose = wrapping.KeyPurpose_Verify
	)
	testCtx := context.Background()
	testPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	marshKey, err := x509.MarshalPKIXPublicKey(testPubKey)
	require.NoError(t, err)
	testPubKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tests := []struct {
		name            string
		pubKey          ed25519.PublicKey
		opt             []wrapping.Option
		want            *Verifier
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:   "success-with-opts",
			pubKey: testPubKey,
			opt: []wrapping.Option{
				WithPubKey(testPubKey),
				wrapping.WithKeyId(testKeyId),
				wrapping.WithKeyPurposes(testKeyPurpose),
				wrapping.WithKeyType(wrapping.KeyType_Ed25519),
			},
			want: &Verifier{
				pubKey:      testPubKey,
				keyPurposes: []wrapping.KeyPurpose{testKeyPurpose},
				keyId:       testKeyId,
				keyType:     wrapping.KeyType_Ed25519,
			},
		},
		{
			name: "success-with-local-opts-and-config",
			opt: []wrapping.Option{
				WithPubKey(testPubKey2),
				wrapping.WithConfigMap(map[string]string{
					ConfigKeyId:       testKeyId,
					ConfigKeyPurposes: wrapping.KeyPurpose_name[int32(wrapping.KeyPurpose_Verify)],
					ConfigPubKey:      string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: marshKey})),
				}),
			},
			want: &Verifier{
				pubKey:      testPubKey2,
				keyPurposes: []wrapping.KeyPurpose{testKeyPurpose},
				keyId:       testKeyId,
				keyType:     wrapping.KeyType_Ed25519,
			},
		},
		{
			name: "success-with-wrapping-opts-and-config",
			opt: []wrapping.Option{
				wrapping.WithKeyId("wrapping-key-id"),
				wrapping.WithKeyPurposes(wrapping.KeyPurpose_MAC),
				wrapping.WithConfigMap(map[string]string{
					ConfigKeyId:       testKeyId,
					ConfigKeyPurposes: wrapping.KeyPurpose_name[int32(wrapping.KeyPurpose_Verify)],
					ConfigPubKey:      string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: marshKey})),
				}),
			},
			want: &Verifier{
				pubKey:      testPubKey,
				keyPurposes: []wrapping.KeyPurpose{testKeyPurpose},
				keyId:       testKeyId,
				keyType:     wrapping.KeyType_Ed25519,
			},
		},
		{
			name:   "invalid-pub-key",
			pubKey: testPubKey,
			opt: []wrapping.Option{
				WithPubKey([]byte("invalid-pub-key")),
				wrapping.WithKeyId(testKeyId),
				wrapping.WithKeyPurposes(testKeyPurpose),
				wrapping.WithKeyType(wrapping.KeyType_Ed25519),
			},
			want: &Verifier{
				pubKey:      testPubKey,
				keyPurposes: []wrapping.KeyPurpose{testKeyPurpose},
				keyId:       testKeyId,
				keyType:     wrapping.KeyType_Ed25519,
			},
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "expected public key with 32 bytes and got 15",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewVerifier(testCtx, tc.opt...)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(got)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func TestVerifier_SetConfig(t *testing.T) {
	t.Parallel()
	const (
		testKeyId      = "key-id"
		testKeyPurpose = wrapping.KeyPurpose_Sign
	)
	testCtx := context.Background()
	testPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	marshKey, err := x509.MarshalPKIXPublicKey(testPubKey)
	require.NoError(t, err)
	tests := []struct {
		name            string
		opt             []wrapping.Option
		verifier        *Verifier
		wantCfg         *wrapping.WrapperConfig
		wantVerifier    *Verifier
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "success-with-options",
			opt: []wrapping.Option{
				WithPubKey(testPubKey),
				wrapping.WithKeyId(testKeyId),
				wrapping.WithKeyPurposes(testKeyPurpose),
			},
			verifier: func() *Verifier {
				testVerifier, err := NewVerifier(testCtx, WithPubKey(testPubKey))
				require.NoError(t, err)
				return testVerifier
			}(),
			wantCfg: &wrapping.WrapperConfig{
				Metadata: map[string]string{
					ConfigPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: marshKey})),
				},
			},
			wantVerifier: func() *Verifier {
				testSigner, err := NewVerifier(testCtx, WithPubKey(testPubKey), wrapping.WithKeyId(testKeyId), wrapping.WithKeyPurposes(testKeyPurpose))
				require.NoError(t, err)
				return testSigner
			}(),
		},
		{
			name: "success-with-config-map",
			opt: []wrapping.Option{
				wrapping.WithConfigMap(map[string]string{
					ConfigKeyId:       testKeyId,
					ConfigKeyPurposes: wrapping.KeyPurpose_name[int32(wrapping.KeyPurpose_Sign)],
					ConfigPubKey:      string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: marshKey})),
				}),
			},
			verifier: func() *Verifier {
				testSigner, err := NewVerifier(testCtx, WithPubKey(testPubKey))
				require.NoError(t, err)
				return testSigner
			}(),
			wantCfg: &wrapping.WrapperConfig{
				Metadata: map[string]string{
					ConfigPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: marshKey})),
				},
			},
			wantVerifier: func() *Verifier {
				testSigner, err := NewVerifier(testCtx, WithPubKey(testPubKey), wrapping.WithKeyId(testKeyId), wrapping.WithKeyPurposes(testKeyPurpose))
				require.NoError(t, err)
				return testSigner
			}(),
		},
		{
			name: "invalid-pub-key",
			opt: []wrapping.Option{
				WithPubKey([]byte("invalid-pub-key")),
				wrapping.WithKeyId(testKeyId),
				wrapping.WithKeyPurposes(testKeyPurpose),
			},
			verifier: func() *Verifier {
				testVerifier, err := NewVerifier(testCtx, WithPubKey(testPubKey))
				require.NoError(t, err)
				return testVerifier
			}(),
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "expected public key with 32 bytes and got 15",
		},
		{
			name: "missing-pub-key",
			opt: []wrapping.Option{
				wrapping.WithKeyId(testKeyId),
				wrapping.WithKeyPurposes(testKeyPurpose),
			},
			verifier: func() *Verifier {
				testVerifier, err := NewVerifier(testCtx, WithPubKey(testPubKey))
				require.NoError(t, err)
				return testVerifier
			}(),
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing public key",
		},
		{
			name: "invalid-pub-key",
			opt: []wrapping.Option{
				wrapping.WithKeyId(testKeyId),
				wrapping.WithKeyPurposes(testKeyPurpose),
			},
			verifier: func() *Verifier {
				testVerifier, err := NewVerifier(testCtx, WithPubKey(testPubKey))
				require.NoError(t, err)
				return testVerifier
			}(),
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing public key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotCfg, err := tc.verifier.SetConfig(testCtx, tc.opt...)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(gotCfg)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.wantCfg, gotCfg)
			assert.Equal(tc.wantVerifier, tc.verifier)
		})
	}
}

func TestVerifier_KeyBytes(t *testing.T) {
	t.Parallel()
	const (
		testKeyId      = "key-id"
		testKeyPurpose = wrapping.KeyPurpose_Sign
	)
	testCtx := context.Background()
	testPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name            string
		opt             []wrapping.Option
		verifier        *Verifier
		wantBytes       []byte
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "success",
			verifier: func() *Verifier {
				testVerifier, err := NewVerifier(testCtx, WithPubKey(testPubKey))
				require.NoError(t, err)
				return testVerifier
			}(),
			wantBytes: []byte(testPubKey),
		},
		{
			name:            "missing-bytes",
			verifier:        &Verifier{},
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing bytes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotBytes, err := tc.verifier.KeyBytes(testCtx)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(gotBytes)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.wantBytes, gotBytes)
		})
	}
}
