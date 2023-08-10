// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package tencentcloudkms

import (
	"context"
	"os"
	"reflect"
	"testing"
)

// This test executes real calls. The calls themselves should be free,
// but the KMS key used is generally not free. TencentCloud doesn't publish
// the price but it can be assumed to be around $1/month because that's
// what AWS charges for the same.
//
// To run this test, the following env variables need to be set:
//   - TENCENTCLOUD_KMS_KEY_ID
//   - TENCENTCLOUD_SECRET_ID
//   - TENCENTCLOUD_SECRET_KEY
//   - TENCENTCLOUD_SECURITY_TOKEN (required when using session token)
//   - TENCENTCLOUD_REGION (ap-guangzhou if not specify)
func TestAccTencentCloudKMSWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	_, err := s.SetConfig(context.Background())
	if err != nil {
		t.Fatalf("err : %s", err)
	}

	input := []byte("tencentcloud")
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
}
