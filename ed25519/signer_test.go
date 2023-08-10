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

func Test_NewSigner(t *testing.T) {
	t.Parallel()
	const (
		testKeyId      = "key-id"
		testKeyPurpose = wrapping.KeyPurpose_Sign
	)
	testCtx := context.Background()
	_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	marshKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
	require.NoError(t, err)

	_, testPrivKey2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name            string
		opt             []wrapping.Option
		wantSigner      *Signer
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "success-with-opts",
			opt: []wrapping.Option{
				WithPrivKey(testPrivKey),
				wrapping.WithKeyId(testKeyId),
				wrapping.WithKeyPurposes(testKeyPurpose),
				wrapping.WithKeyType(wrapping.KeyType_Ed25519),
			},
			wantSigner: &Signer{
				privKey:     testPrivKey,
				keyPurposes: []wrapping.KeyPurpose{testKeyPurpose},
				keyId:       testKeyId,
				keyType:     wrapping.KeyType_Ed25519,
			},
		},
		{
			name: "success-with-config",
			opt: []wrapping.Option{
				wrapping.WithConfigMap(map[string]string{
					ConfigKeyId:       testKeyId,
					ConfigKeyPurposes: wrapping.KeyPurpose_name[int32(wrapping.KeyPurpose_Sign)],
					ConfigPrivKey:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshKey})),
				}),
			},
			wantSigner: &Signer{
				privKey:     testPrivKey,
				keyPurposes: []wrapping.KeyPurpose{testKeyPurpose},
				keyId:       testKeyId,
				keyType:     wrapping.KeyType_Ed25519,
			},
		},
		{
			name: "success-with-local-opts-and-config",
			opt: []wrapping.Option{
				WithPrivKey(testPrivKey2),
				wrapping.WithConfigMap(map[string]string{
					ConfigKeyId:       testKeyId,
					ConfigKeyPurposes: wrapping.KeyPurpose_name[int32(wrapping.KeyPurpose_Sign)],
					ConfigPrivKey:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshKey})),
				}),
			},
			wantSigner: &Signer{
				privKey:     testPrivKey2,
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
					ConfigKeyPurposes: wrapping.KeyPurpose_name[int32(wrapping.KeyPurpose_Sign)],
					ConfigPrivKey:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshKey})),
				}),
			},
			wantSigner: &Signer{
				privKey:     testPrivKey,
				keyPurposes: []wrapping.KeyPurpose{testKeyPurpose},
				keyId:       testKeyId,
				keyType:     wrapping.KeyType_Ed25519,
			},
		},
		{
			name: "invalid-private-key",
			opt: []wrapping.Option{
				WithPrivKey([]byte("invalid-priv-key")),
				wrapping.WithKeyId(testKeyId),
				wrapping.WithKeyPurposes(testKeyPurpose),
				wrapping.WithKeyType(wrapping.KeyType_Ed25519),
			},
			wantSigner: &Signer{
				privKey:     testPrivKey,
				keyPurposes: []wrapping.KeyPurpose{testKeyPurpose},
				keyId:       testKeyId,
				keyType:     wrapping.KeyType_Ed25519,
			},
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "expected private key with 64 bytes and got 16",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotSigner, err := NewSigner(testCtx, tc.opt...)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(gotSigner)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.wantSigner, gotSigner)
		})
	}
}

func Test_SignVerify(t *testing.T) {
	t.Parallel()
	const (
		testKeyId      = "key-id"
		testKeyPurpose = wrapping.KeyPurpose_Sign
	)
	testPt := []byte("test-plaintext")
	testCtx := context.Background()
	testPubKey, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	testSigner, err := NewSigner(testCtx, WithPrivKey(testPrivKey), wrapping.WithKeyId(testKeyId), wrapping.WithKeyPurposes(testKeyPurpose), wrapping.WithKeyType(wrapping.KeyType_Ed25519))
	require.NoError(t, err)
	testVerifier, err := NewVerifier(testCtx, WithPubKey(testPubKey))
	require.NoError(t, err)
	tests := []struct {
		name            string
		signer          wrapping.SigInfoSigner
		msg             []byte
		sig             *wrapping.SigInfo
		opt             []wrapping.Option
		verifier        wrapping.SigInfoVerifier
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:   "success-all-opts",
			signer: testSigner,
			msg:    testPt,
			sig: func() *wrapping.SigInfo {
				si := TestSigInfo(t, testPrivKey, testPt, wrapping.WithKeyId(testKeyId), wrapping.WithKeyPurposes(wrapping.KeyPurpose_Sign), wrapping.WithKeyType(wrapping.KeyType_Ed25519))
				return si
			}(),
			verifier: testVerifier,
		},
		{
			name: "invalid-purpose",
			signer: func() *Signer {
				testSigner, err := NewSigner(testCtx, WithPrivKey(testPrivKey), wrapping.WithKeyPurposes(wrapping.KeyPurpose_MAC))
				require.NoError(t, err)
				return testSigner
			}(),
			msg: testPt,
			sig: func() *wrapping.SigInfo {
				si := TestSigInfo(t, testPrivKey, testPt, wrapping.WithKeyId(testKeyId), wrapping.WithKeyPurposes(wrapping.KeyPurpose_Sign), wrapping.WithKeyType(wrapping.KeyType_Ed25519))
				return si
			}(),
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "key's supported purposes \"MAC\" does not contain Sign",
		},
		{
			name:            "missing-msg",
			signer:          testSigner,
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing message",
		},
		{
			name:            "nil-private-key",
			signer:          &Signer{},
			msg:             testPt,
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing private key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotSig, err := tc.signer.Sign(testCtx, tc.msg, tc.opt...)
			if tc.wantErr {
				require.Error(err)
				assert.Empty(gotSig)
				if tc.wantErrIs != nil {
					assert.ErrorIs(err, tc.wantErrIs)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.sig, gotSig)
			gotVerify, err := tc.verifier.Verify(testCtx, tc.msg, gotSig)
			require.NoError(err)
			assert.True(gotVerify)

			assert.True(ed25519.Verify(tc.verifier.(*Verifier).pubKey, tc.msg, gotSig.Signature))
		})
	}

	verifyErrorTests := []struct {
		name            string
		verifier        wrapping.SigInfoVerifier
		msg             []byte
		sig             *wrapping.SigInfo
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "missing-pub-key",
			verifier:        &Verifier{},
			msg:             testPt,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing public key",
		},
		{
			name:            "missing-msg",
			verifier:        testVerifier,
			sig:             &wrapping.SigInfo{},
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing message",
		},
		{
			name:            "missing-sig-info",
			verifier:        testVerifier,
			msg:             testPt,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing sig info",
		},
		{
			name: "invalid-purpose",
			verifier: func() *Verifier {
				testVerifier, err := NewVerifier(testCtx, WithPubKey(testPubKey), wrapping.WithKeyPurposes(wrapping.KeyPurpose_MAC))
				require.NoError(t, err)
				return testVerifier
			}(),
			msg: testPt,
			sig: func() *wrapping.SigInfo {
				si := TestSigInfo(t, testPrivKey, testPt, wrapping.WithKeyId(testKeyId), wrapping.WithKeyPurposes(wrapping.KeyPurpose_Sign), wrapping.WithKeyType(wrapping.KeyType_Ed25519))
				return si
			}(),
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "key's supported purposes \"MAC\" does not contain Verify",
		},
	}
	for _, tc := range verifyErrorTests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.verifier.Verify(testCtx, tc.msg, tc.sig)
			require.Error(err)
			assert.Empty(got)
			if tc.wantErrIs != nil {
				assert.ErrorIs(err, tc.wantErrIs)
			}
			if tc.wantErrContains != "" {
				assert.Contains(err.Error(), tc.wantErrContains)
			}
		})
	}
}

func TestSigner_SetConfig(t *testing.T) {
	t.Parallel()
	const (
		testKeyId      = "key-id"
		testKeyPurpose = wrapping.KeyPurpose_Sign
	)
	testCtx := context.Background()
	_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	marshKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
	require.NoError(t, err)
	tests := []struct {
		name            string
		opt             []wrapping.Option
		signer          *Signer
		wantCfg         *wrapping.WrapperConfig
		wantSigner      *Signer
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "success-with-options",
			opt: []wrapping.Option{
				WithPrivKey(testPrivKey),
				wrapping.WithKeyId(testKeyId),
				wrapping.WithKeyPurposes(testKeyPurpose),
			},
			signer: func() *Signer {
				testSigner, err := NewSigner(testCtx, WithPrivKey(testPrivKey))
				require.NoError(t, err)
				return testSigner
			}(),
			wantCfg: &wrapping.WrapperConfig{
				Metadata: map[string]string{},
			},
			wantSigner: func() *Signer {
				testSigner, err := NewSigner(testCtx, WithPrivKey(testPrivKey), wrapping.WithKeyId(testKeyId), wrapping.WithKeyPurposes(testKeyPurpose))
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
					ConfigPrivKey:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshKey})),
				}),
			},
			signer: func() *Signer {
				testSigner, err := NewSigner(testCtx, WithPrivKey(testPrivKey))
				require.NoError(t, err)
				return testSigner
			}(),
			wantCfg: &wrapping.WrapperConfig{
				Metadata: map[string]string{},
			},
			wantSigner: func() *Signer {
				testSigner, err := NewSigner(testCtx, WithPrivKey(testPrivKey), wrapping.WithKeyId(testKeyId), wrapping.WithKeyPurposes(testKeyPurpose))
				require.NoError(t, err)
				return testSigner
			}(),
		},
		{
			name: "invalid-priv-key",
			opt: []wrapping.Option{
				WithPrivKey([]byte("invalid-priv-key")),
				wrapping.WithKeyId(testKeyId),
				wrapping.WithKeyPurposes(testKeyPurpose),
			},
			signer: func() *Signer {
				testSigner, err := NewSigner(testCtx, WithPrivKey(testPrivKey))
				require.NoError(t, err)
				return testSigner
			}(),
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "expected private key with 64 bytes and got 16",
		},
		{
			name: "missing-priv-key",
			opt: []wrapping.Option{
				wrapping.WithKeyId(testKeyId),
				wrapping.WithKeyPurposes(testKeyPurpose),
			},
			signer: func() *Signer {
				testSigner, err := NewSigner(testCtx, WithPrivKey(testPrivKey))
				require.NoError(t, err)
				return testSigner
			}(),
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing private key",
		},
		{
			name: "missing-key-purpose",
			opt: []wrapping.Option{
				WithPrivKey(testPrivKey),
				wrapping.WithKeyId(testKeyId),
			},
			signer: func() *Signer {
				testSigner, err := NewSigner(testCtx, WithPrivKey(testPrivKey))
				require.NoError(t, err)
				return testSigner
			}(),
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing key purpose",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotCfg, err := tc.signer.SetConfig(testCtx, tc.opt...)
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
			assert.Equal(tc.wantSigner, tc.signer)
		})
	}
}

func TestSigner_KeyBytes(t *testing.T) {
	t.Parallel()
	const (
		testKeyId      = "key-id"
		testKeyPurpose = wrapping.KeyPurpose_Sign
	)
	testCtx := context.Background()
	_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name            string
		opt             []wrapping.Option
		signer          *Signer
		wantBytes       []byte
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "success",
			signer: func() *Signer {
				testSigner, err := NewSigner(testCtx, WithPrivKey(testPrivKey))
				require.NoError(t, err)
				return testSigner
			}(),
			wantBytes: []byte(testPrivKey),
		},
		{
			name:            "missing-bytes",
			signer:          &Signer{},
			wantErr:         true,
			wantErrIs:       wrapping.ErrInvalidParameter,
			wantErrContains: "missing bytes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotBytes, err := tc.signer.KeyBytes(testCtx)
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
