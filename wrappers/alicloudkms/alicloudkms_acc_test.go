package alicloudkms

import (
	"context"
	"os"
	"reflect"
	"testing"
)

// This test executes real calls. The calls themselves should be free,
// but the KMS key used is generally not free. Alibaba doesn't publish
// the price but it can be assumed to be around $1/month because that's
// what AWS charges for the same.
//
// To run this test, the following env variables need to be set:
//   - VAULT_ALICLOUDKMS_SEAL_KEY_ID or ALICLOUDKMS_WRAPPING_KEY_ID
//   - ALICLOUD_REGION
//   - ALICLOUD_ACCESS_KEY
//   - ALICLOUD_SECRET_KEY
func TestAccAliCloudKMSWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	s := NewWrapper(nil)
	_, err := s.SetConfig(nil)
	if err != nil {
		t.Fatalf("err : %s", err)
	}

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
}
