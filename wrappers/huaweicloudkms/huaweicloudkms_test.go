package huaweicloudkms

import (
	"context"
	"encoding/base64"
	"os"
	"reflect"
	"testing"

	kmsKeys "github.com/huaweicloud/golangsdk/openstack/kms/v1/keys"
)

const huaweiCloudTestKeyID = "foo"

func TestHuaweiCloudKMSWrapper(t *testing.T) {
	s := NewWrapper(nil)
	s.client = &mockHuaweiCloudKMSWrapperClient{}

	if _, err := s.SetConfig(nil); err == nil {
		t.Fatal("expected error when HuaweiCloudKMSWrapper key ID is not provided")
	}

	// Set the key
	if err := os.Setenv(EnvHuaweiCloudKMSWrapperKeyID, huaweiCloudTestKeyID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Unsetenv(EnvHuaweiCloudKMSWrapperKeyID); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := s.SetConfig(nil); err != nil {
		t.Fatal(err)
	}
}

func TestHuaweiCloudKMSWrapper_Lifecycle(t *testing.T) {
	s := NewWrapper(nil)
	s.client = &mockHuaweiCloudKMSWrapperClient{}

	if err := os.Setenv(EnvHuaweiCloudKMSWrapperKeyID, huaweiCloudTestKeyID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Unsetenv(EnvHuaweiCloudKMSWrapperKeyID); err != nil {
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

type mockHuaweiCloudKMSWrapperClient struct {
}

func (m *mockHuaweiCloudKMSWrapperClient) getRegion() string {
	return ""
}

func (m *mockHuaweiCloudKMSWrapperClient) getProject() string {
	return ""
}

// Encrypt is a mocked call that returns a base64 encoded string.
func (m *mockHuaweiCloudKMSWrapperClient) encrypt(keyID, plainText string) (encryptResponse, error) {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(plainText)))
	base64.StdEncoding.Encode(encoded, []byte(plainText))

	output := encryptResponse{KeyID: keyID, Ciphertext: string(encoded)}
	return output, nil
}

// Decrypt is a mocked call that returns a decoded base64 string.
func (m *mockHuaweiCloudKMSWrapperClient) decrypt(cipherText string) (string, error) {
	decLen := base64.StdEncoding.DecodedLen(len(cipherText))
	decoded := make([]byte, decLen)
	len, err := base64.StdEncoding.Decode(decoded, []byte(cipherText))
	if err != nil {
		return "", err
	}

	if len < decLen {
		decoded = decoded[:len]
	}

	return string(decoded), nil
}

// DescribeKey is a mocked call that returns the keyID.
func (m *mockHuaweiCloudKMSWrapperClient) describeKey(keyID string) (*kmsKeys.Key, error) {
	return &kmsKeys.Key{KeyID: keyID}, nil
}
