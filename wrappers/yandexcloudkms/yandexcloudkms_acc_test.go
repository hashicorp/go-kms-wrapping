package yandexcloudkms

import (
	"context"
	"os"
	"reflect"
	"testing"
)

// This test executes real calls. The calls themselves should be free,
// but the KMS key used is generally not free. Please see the document
// of Yandex.Cloud to get the price of KMS.
//
// To run this test, the following env variables need to be set:
//   - YANDEXCLOUD_KMS_KEY_ID
func TestAccYandexCloudKMSWrapper_Lifecycle(t *testing.T) {
	if os.Getenv(EnvYandexCloudKMSKeyID) == "" {
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
