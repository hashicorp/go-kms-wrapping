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
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster/docker"
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

func (m *testTransitClient) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	v, err := m.wrap.Encrypt(ctx, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return []byte(fmt.Sprintf("v1:%s:%s", m.keyID, string(v.Ciphertext))), nil
}

func (m *testTransitClient) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	splitKey := strings.Split(string(ciphertext), ":")
	if len(splitKey) != 3 {
		return nil, errors.New("invalid ciphertext returned")
	}

	data := &wrapping.BlobInfo{
		Ciphertext: []byte(splitKey[2]),
	}
	v, err := m.wrap.Decrypt(ctx, data, nil)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func getTestCluster(t *testing.T) (*docker.DockerCluster, *docker.DockerClusterNode, *api.Client) {
	opts := docker.DefaultOptions(t)
	opts.ClusterOptions.NumCores = 1
	cluster := docker.NewTestDockerCluster(t, opts)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	nodeIdx, err := testcluster.WaitForActiveNode(ctx, cluster)
	require.NoError(t, err, "no cluster node became active in timeout window")

	node := cluster.ClusterNodes[nodeIdx]
	client := node.APIClient()

	client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	})

	return cluster, node, client
}

func TestTransitWrapper_Lifecycle(t *testing.T) {
	// Set up wrapper
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

	// Test keyId prefix (can't use the option/SetConfig however )
	s.keyIdPrefix = "test/"
	_, err = s.Encrypt(context.Background(), input)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	kid, err = s.KeyId(context.Background())
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if kid != "test/"+keyId {
		t.Fatalf("key id does not match: expected %s, got %s", keyId, kid)
	}
}

func TestSetConfig(t *testing.T) {
	// Set up a shared Vault cluster with Transit.
	cluster, _, client := getTestCluster(t)
	defer cluster.Cleanup()

	testWithMountPath := "transit/"
	testWithAddress := client.Address()
	testWithKeyName := "example-key"
	testWithDisableRenewal := "true"
	testWithToken := client.Token()

	os.Setenv("BAO_CACERT_BYTES", string(cluster.CACertPEM))

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
			},
		},
		{
			name: "missing-key-name",
			opts: []wrapping.Option{
				WithAddress(testWithAddress),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
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
			},
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
			},
		},
		{
			name: "error-SetConfig-bad-scheme",
			opts: []wrapping.Option{
				WithAddress("bad-scheme"),
				WithToken(testWithToken),
				WithMountPath(testWithMountPath),
				WithKeyName(testWithKeyName),
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
				WithKeyIdPrefix("test/"),
			},
		},
		{
			name: "success-without-opts",
			setup: func(t *testing.T) {
				require.NoError(t, os.Setenv(EnvTransitWrapperAddr, testWithAddress))
				require.NoError(t, os.Setenv(EnvTransitWrapperToken, testWithToken))
				require.NoError(t, os.Setenv(EnvTransitWrapperDisableRenewal, testWithDisableRenewal))
				require.NoError(t, os.Setenv(EnvTransitWrapperKeyName, testWithKeyName))
				require.NoError(t, os.Setenv(EnvTransitWrapperMountPath, testWithMountPath))
				t.Cleanup(func() { os.Unsetenv(EnvTransitWrapperAddr) })
				t.Cleanup(func() { os.Unsetenv(EnvTransitWrapperToken) })
				t.Cleanup(func() { os.Unsetenv(EnvTransitWrapperDisableRenewal) })
				t.Cleanup(func() { os.Unsetenv(EnvTransitWrapperKeyName) })
				t.Cleanup(func() { os.Unsetenv(EnvTransitWrapperMountPath) })
			},
			opts: []wrapping.Option{},
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

func TestContextCancellation(t *testing.T) {
	// Set up a shared Vault cluster with Transit.
	cluster, _, client := getTestCluster(t)
	defer cluster.Cleanup()

	testWithMountPath := "transit/"
	testWithAddress := client.Address()
	testWithKeyName := "example-key"
	testWithToken := client.Token()

	os.Setenv("BAO_CACERT_BYTES", string(cluster.CACertPEM))

	t.Run("Encrypt stops when the context is cancelled", func(t *testing.T) {
		_, require := assert.New(t), require.New(t)
		w := NewWrapper()
		_, err := w.SetConfig(
			context.Background(),
			WithAddress(testWithAddress),
			WithToken(testWithToken),
			WithMountPath(testWithMountPath),
			WithKeyName(testWithKeyName),
			WithKeyIdPrefix("test/"),
		)
		require.NoError(err)
		testPt := []byte("test-plaintext")
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = w.Encrypt(canceledCtx, testPt)
		require.Error(err)
		require.ErrorIs(err, context.Canceled)
	})
	t.Run("Decrypt stops when the context is cancelled", func(t *testing.T) {
		_, require := assert.New(t), require.New(t)
		w := NewWrapper()
		_, err := w.SetConfig(
			context.Background(),
			WithAddress(testWithAddress),
			WithToken(testWithToken),
			WithMountPath(testWithMountPath),
			WithKeyName(testWithKeyName),
			WithKeyIdPrefix("test/"),
		)
		require.NoError(err)
		testPt := []byte("test-plaintext")
		blob, err := w.Encrypt(context.Background(), testPt)
		require.NoError(err)
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = w.Decrypt(canceledCtx, blob)
		require.Error(err)
		require.ErrorIs(err, context.Canceled)
	})
}
