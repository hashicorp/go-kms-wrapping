package transit

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping"
)

type testTransitClient struct {
	keyID string
	wrap  wrapping.Wrapper
}

func newTestTransitClient(keyID string) *testTransitClient {
	return &testTransitClient{
		keyID: keyID,
		wrap:  wrapping.NewTestWrapper(nil),
	}
}

func (m *testTransitClient) Close() {}

func (m *testTransitClient) Encrypt(plaintext []byte) ([]byte, error) {
	v, err := m.wrap.Encrypt(context.Background(), plaintext, nil)
	if err != nil {
		return nil, err
	}

	return []byte(fmt.Sprintf("v1:%s:%s", m.keyID, string(v.Ciphertext))), nil
}

func (m *testTransitClient) Decrypt(ciphertext []byte) ([]byte, error) {
	splitKey := strings.Split(string(ciphertext), ":")
	if len(splitKey) != 3 {
		return nil, errors.New("invalid ciphertext returned")
	}

	data := &wrapping.EncryptedBlobInfo{
		Ciphertext: []byte(splitKey[2]),
	}
	v, err := m.wrap.Decrypt(context.Background(), data, nil)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func TestTransitWrapper_Lifecycle(t *testing.T) {
	s := NewWrapper(nil)

	keyID := "test-key"
	s.client = newTestTransitClient(keyID)

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

	if s.KeyID() != keyID {
		t.Fatalf("key id does not match: expected %s, got %s", keyID, s.KeyID())
	}
}
