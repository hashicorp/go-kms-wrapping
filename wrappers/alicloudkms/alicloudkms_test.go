package alicloudkms

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

const aliCloudTestKeyId = "foo"

func TestAliCloudKmsWrapper(t *testing.T) {
	s := NewWrapper()
	s.client = &mockAliCloudKmsWrapperClient{
		keyId: aliCloudTestKeyId,
	}

	if _, err := s.SetConfig(nil); err == nil {
		t.Fatal("expected error when AliCloudKMSWrapper key ID is not provided")
	}

	// Set the key
	if err := os.Setenv(EnvAliCloudKmsWrapperKeyId, aliCloudTestKeyId); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Unsetenv(EnvAliCloudKmsWrapperKeyId); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := s.SetConfig(nil); err != nil {
		t.Fatal(err)
	}
}

func TestAliCloudKmsWrapper_Lifecycle(t *testing.T) {
	s := NewWrapper()
	s.client = &mockAliCloudKmsWrapperClient{
		keyId: aliCloudTestKeyId,
	}

	if err := os.Setenv(EnvAliCloudKmsWrapperKeyId, aliCloudTestKeyId); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Unsetenv(EnvAliCloudKmsWrapperKeyId); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := s.SetConfig(nil); err != nil {
		t.Fatal(err)
	}

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
}

type mockAliCloudKmsWrapperClient struct {
	keyId string
}

// Encrypt is a mocked call that returns a base64 encoded string.
func (m *mockAliCloudKmsWrapperClient) Encrypt(request *kms.EncryptRequest) (response *kms.EncryptResponse, err error) {
	m.keyId = request.KeyId

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(request.Plaintext)))
	base64.StdEncoding.Encode(encoded, []byte(request.Plaintext))

	output := kms.CreateEncryptResponse()
	output.CiphertextBlob = string(encoded)
	output.KeyId = request.KeyId
	return output, nil
}

// Decrypt is a mocked call that returns a decoded base64 string.
func (m *mockAliCloudKmsWrapperClient) Decrypt(request *kms.DecryptRequest) (response *kms.DecryptResponse, err error) {
	decLen := base64.StdEncoding.DecodedLen(len(request.CiphertextBlob))
	decoded := make([]byte, decLen)
	len, err := base64.StdEncoding.Decode(decoded, []byte(request.CiphertextBlob))
	if err != nil {
		return nil, err
	}

	if len < decLen {
		decoded = decoded[:len]
	}

	output := kms.CreateDecryptResponse()
	output.KeyId = m.keyId
	output.Plaintext = string(decoded)
	return output, nil
}

// DescribeKey is a mocked call that returns the keyID.
func (m *mockAliCloudKmsWrapperClient) DescribeKey(request *kms.DescribeKeyRequest) (response *kms.DescribeKeyResponse, err error) {
	if m.keyId == "" {
		return nil, errors.New("key not found")
	}
	output := kms.CreateDescribeKeyResponse()
	output.KeyMetadata = kms.KeyMetadata{
		KeyId: m.keyId,
	}
	return output, nil
}
