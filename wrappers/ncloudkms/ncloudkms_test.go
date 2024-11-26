package ncloudkms

import (
	"context"
	"reflect"
	"testing"
)

// To run this test, the following env variables need to be set:
//   - NCLOUD_KMS_KEY_TAG
//   - NCLOUD_ACCESS_KEY
//   - NCLOUD_SECRET_KEY
func TestAccAwsKmsWrapper_Lifecycle(t *testing.T) {
	s := NewWrapper()
	testEncryptionRoundTrip(t, s)
}

func testEncryptionRoundTrip(t *testing.T, w *Wrapper) {
	w.SetConfig(context.Background())
	input := []byte("foo")
	swi, err := w.Encrypt(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := w.Decrypt(context.Background(), swi, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}
