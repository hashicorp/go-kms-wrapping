// Copyright © 2019, Oracle and/or its affiliates.
package ocikms

import (
	"errors"
	"net/http"
	"os"
	"reflect"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/oracle/oci-go-sdk/v60/common"
	"golang.org/x/net/context"
)

// fakeOCIResponse implements common.OCIResponse and returns the embedded
// *http.Response (which may itself be nil) from HTTPResponse().
type fakeOCIResponse struct {
	httpResp *http.Response
}

func (f *fakeOCIResponse) HTTPResponse() *http.Response { return f.httpResp }

func TestShouldRetryOn5xx(t *testing.T) {
	tests := []struct {
		name string
		op   common.OCIOperationResponse
		want bool
	}{
		{
			name: "no error and no response",
			op:   common.OCIOperationResponse{},
			want: false,
		},
		{
			// Regression: the OCI SDK produces OCIOperationResponse{Error: ..., Response: nil}
			// when the configuration provider (Instance/Resource Principal) fails to build
			// credentials before any HTTP round-trip occurs. The retry predicate must
			// not dereference Response in that case.
			name: "error with nil response does not panic and does not retry",
			op: common.OCIOperationResponse{
				Error:    errors.New("failed to build signer"),
				Response: nil,
			},
			want: false,
		},
		{
			// Defensive: even when Response is non-nil, its HTTPResponse() may be nil
			// (for example when the SDK populated a typed response without an
			// http.Response).
			name: "error with response but nil HTTPResponse does not retry",
			op: common.OCIOperationResponse{
				Error:    errors.New("transport failure"),
				Response: &fakeOCIResponse{httpResp: nil},
			},
			want: false,
		},
		{
			name: "error with 4xx response does not retry",
			op: common.OCIOperationResponse{
				Error:    errors.New("unauthorized"),
				Response: &fakeOCIResponse{httpResp: &http.Response{StatusCode: http.StatusUnauthorized}},
			},
			want: false,
		},
		{
			name: "error with 5xx response retries",
			op: common.OCIOperationResponse{
				Error:    errors.New("internal server error"),
				Response: &fakeOCIResponse{httpResp: &http.Response{StatusCode: http.StatusInternalServerError}},
			},
			want: true,
		},
		{
			name: "no error but 5xx response does not retry",
			op: common.OCIOperationResponse{
				Response: &fakeOCIResponse{httpResp: &http.Response{StatusCode: http.StatusInternalServerError}},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// The historical bug was a panic, so guard against re-introduction.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("shouldRetryOn5xx panicked: %v", r)
				}
			}()
			if got := shouldRetryOn5xx(tc.op); got != tc.want {
				t.Fatalf("shouldRetryOn5xx() = %v, want %v", got, tc.want)
			}
		})
	}
}

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
