package yandexcloudkms

import (
	"context"
	"os"
	"reflect"
	"testing"
)

// This test executes real calls.
// Pricing policy for Yandex.Cloud KMS: https://cloud.yandex.com/docs/kms/pricing
//
// To run this test, the following env variables need to be set:
//   - YANDEXCLOUD_KMS_KEY_ID
//   - YANDEXCLOUD_OAUTH_TOKEN (required only for Yandex account authentication)
//   - YANDEXCLOUD_SERVICE_ACCOUNT_KEY_FILE (required only for service account authentication)
//
// Yandex account OAuth token can be received here:
//   https://oauth.yandex.com/authorize?response_type=token&client_id=1a6990aa636648e9b2ef855fa7bec2fb
// Service account key file can be created with Yandex.Cloud CLI:
//   $ yc iam key create --service-account-name my-robot -o my-robot-key.json
// More about authentication in Yandex.Cloud: https://cloud.yandex.com/docs/iam/concepts/authorization/#authentication
//
func TestAccYandexCloudKMSWrapper_Lifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	wrapper := NewWrapper(nil)
	_, err := wrapper.SetConfig(nil)
	if err != nil {
		t.Fatalf("err : %s", err)
	}

	plaintext := []byte("foo")
	encryptedBlobInfo, err := wrapper.Encrypt(context.Background(), plaintext, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	decrypted, err := wrapper.Decrypt(context.Background(), encryptedBlobInfo, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(plaintext, decrypted) {
		t.Fatalf("expected %s, got %s", plaintext, decrypted)
	}
}
