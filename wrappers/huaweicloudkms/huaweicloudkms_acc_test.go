// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package huaweicloudkms

import (
	"context"
	"os"
	"reflect"
	"testing"
)

// This test executes real calls. The calls themselves should be free,
// but the KMS key used is generally not free. Please see the document
// of Huawei Cloud to get the price of KMS.
//
// To run this test, the following env variables need to be set:
//   - VAULT_HUAWEICLOUDKMS_SEAL_KEY_ID or HUAWEICLOUDKMS_WRAPPER_KEY_ID
//   - HUAWEICLOUD_REGION
//   - HUAWEICLOUD_PROJECT
//   - HUAWEICLOUD_ACCESS_KEY
//   - HUAWEICLOUD_SECRET_KEY
func TestAccHuaweiCloudKmsWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	s := NewWrapper()
	_, err := s.SetConfig(context.Background())
	if err != nil {
		t.Fatalf("err : %s", err)
	}

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
}
