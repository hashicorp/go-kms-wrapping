// Copyright © 2019, Oracle and/or its affiliates.
package ocikms

import (
	"errors"
	"net/http"
	"os"
	"reflect"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/oracle/oci-go-sdk/v65/common"
	"golang.org/x/net/context"
)

/*
* To run these tests, ensure you setup:
* 1. OCI SDK with your credentials. Refer to here:
*		https://docs.cloud.oracle.com/iaas/Content/API/Concepts/sdkconfig.htm
* 2. Go to ocikms folder: vault/vault/seal/ocikms
*		VAULT_OCIKMS_SEAL_KEY_ID="your-kms-key" VAULT_OCIKMS_CRYPTO_ENDPOINT="your-kms-crypto-endpoint" go test
 */

func TestWrapper(t *testing.T) {
	initSeal(t)
}

func TestWrapper_LifeCycle(t *testing.T) {
	s := initSeal(t)

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := s.Decrypt(context.Background(), swi, nil)
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

	pt, err = s.Decrypt(context.Background(), swi)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}

func initSeal(t *testing.T) *Wrapper {
	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	s := NewWrapper()
	_, err := s.SetConfig(context.Background())
	if err == nil {
		t.Fatal("expected error when Wrapper required values are not provided")
	}

	mockConfig := map[string]string{
		"auth_type_api_key": "true",
	}

	_, err = s.SetConfig(context.Background(), wrapping.WithConfigMap(mockConfig))
	if err != nil {
		t.Fatalf("error setting seal config: %v", err)
	}

	return s
}

type stubOCIResponse struct {
	status  int
	nilHTTP bool
}

func (s stubOCIResponse) HTTPResponse() *http.Response {
	if s.nilHTTP {
		return nil
	}
	return &http.Response{StatusCode: s.status}
}

func TestGetRequestMetadata_RetryOn5xx(t *testing.T) {
	errFakeSigner := errors.New("failed to construct authentication signer")
	policy := NewWrapper().getRequestMetadata().RetryPolicy
	if policy == nil || policy.ShouldRetryOperation == nil {
		t.Fatal("expected retry policy with ShouldRetryOperation")
	}

	cases := []struct {
		name string
		resp common.OCIOperationResponse
		want bool
	}{
		{
			name: "nil response does not panic",
			resp: common.OCIOperationResponse{Error: errFakeSigner, Response: nil},
			want: false,
		},
		{
			name: "no error",
			resp: common.OCIOperationResponse{Response: stubOCIResponse{status: 500}},
			want: false,
		},
		{
			name: "error with 500",
			resp: common.OCIOperationResponse{Error: errFakeSigner, Response: stubOCIResponse{status: 500}},
			want: true,
		},
		{
			name: "error with 400",
			resp: common.OCIOperationResponse{Error: errFakeSigner, Response: stubOCIResponse{status: 400}},
			want: false,
		},
		{
			name: "error with nil HTTP response",
			resp: common.OCIOperationResponse{Error: errFakeSigner, Response: stubOCIResponse{nilHTTP: true}},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("ShouldRetryOperation panicked: %v", rec)
				}
			}()
			got := policy.ShouldRetryOperation(tc.resp)
			if got != tc.want {
				t.Fatalf("ShouldRetryOperation() = %v, want %v", got, tc.want)
			}
		})
	}
}
