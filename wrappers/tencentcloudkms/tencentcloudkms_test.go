package tencentcloudkms

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	kms "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/kms/v20190118"
)

const tencentCloudTestKeyID = "tencentcloud-test-key-id"

func TestTencentCloudKMSWrapper(t *testing.T) {
	s := NewWrapper(nil)
	s.client = &mockTencentCloudKMSWrapperClient{
		keyID: common.StringPtr(tencentCloudTestKeyID),
	}

	// Clean the env vars for keyID not found
	tmpKeyID := os.Getenv(PROVIDER_KMS_KEY_ID)
	_ = os.Unsetenv(PROVIDER_KMS_KEY_ID)

	if _, err := s.SetConfig(nil); err == nil {
		t.Fatal("expected error when TencentCloudKMSWrapper keyID is not provided")
	}

	if err := os.Setenv(PROVIDER_KMS_KEY_ID, tencentCloudTestKeyID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Setenv(PROVIDER_KMS_KEY_ID, tmpKeyID); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := s.SetConfig(nil); err != nil {
		t.Fatal(err)
	}
}

func TestTencentCloudKMSWrapper_Lifecycle(t *testing.T) {
	s := NewWrapper(nil)
	s.client = &mockTencentCloudKMSWrapperClient{
		keyID: common.StringPtr(tencentCloudTestKeyID),
	}

	// Clean the env vars for keyID not found
	tmpKeyID := os.Getenv(PROVIDER_KMS_KEY_ID)
	_ = os.Unsetenv(PROVIDER_KMS_KEY_ID)

	if err := os.Setenv(PROVIDER_KMS_KEY_ID, tencentCloudTestKeyID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Setenv(PROVIDER_KMS_KEY_ID, tmpKeyID); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := s.SetConfig(nil); err != nil {
		t.Fatal(err)
	}

	input := []byte("tencentcloud")
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

// mockTencentCloudKMSWrapperClient is a mock client for testing
type mockTencentCloudKMSWrapperClient struct {
	keyID *string
}

// Encrypt is a mocked call that returns a base64 encoded string.
func (m *mockTencentCloudKMSWrapperClient) Encrypt(request *kms.EncryptRequest) (response *kms.EncryptResponse, err error) {
	m.keyID = request.KeyId

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(*request.Plaintext)))
	base64.StdEncoding.Encode(encoded, []byte(*request.Plaintext))

	output := &kms.EncryptResponse{}
	_ = output.FromJsonString(`{"Response": {"KeyId": "` + *request.KeyId + `", "CiphertextBlob": "` + string(encoded) + `"}}`)
	return output, nil
}

// Decrypt is a mocked call that returns a decoded base64 string.
func (m *mockTencentCloudKMSWrapperClient) Decrypt(request *kms.DecryptRequest) (response *kms.DecryptResponse, err error) {
	decLen := base64.StdEncoding.DecodedLen(len(*request.CiphertextBlob))
	decoded := make([]byte, decLen)
	len, err := base64.StdEncoding.Decode(decoded, []byte(*request.CiphertextBlob))
	if err != nil {
		return nil, err
	}

	if len < decLen {
		decoded = decoded[:len]
	}

	output := &kms.DecryptResponse{}
	_ = output.FromJsonString(`{"Response": {"KeyId": "` + *m.keyID + `", "Plaintext": "` + string(decoded) + `"}}`)
	return output, nil
}

// DescribeKey is a mocked call that returns the keyID.
func (m *mockTencentCloudKMSWrapperClient) DescribeKey(request *kms.DescribeKeyRequest) (response *kms.DescribeKeyResponse, err error) {
	if *m.keyID == "" {
		return nil, errors.New("key not found")
	}
	output := &kms.DescribeKeyResponse{}
	_ = output.FromJsonString(`{"Response": {"KeyMetadata": {"KeyId": "` + *m.keyID + `"}}`)
	return output, nil
}
