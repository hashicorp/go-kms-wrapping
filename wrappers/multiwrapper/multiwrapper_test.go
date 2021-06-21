package multiwrapper

import (
	"crypto/rand"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
)

func TestMultiWrapper(t *testing.T) {
	w1Key := make([]byte, 32)
	n, err := rand.Read(w1Key)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	w1 := aead.NewWrapper(nil)
	w1.SetConfig(map[string]string{"key_id": "w1"})
	if err := w1.SetAESGCMKeyBytes(w1Key); err != nil {
		t.Fatal(err)
	}

	w2Key := make([]byte, 32)
	n, err = rand.Read(w2Key)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	w2 := aead.NewWrapper(nil)
	w2.SetConfig(map[string]string{"key_id": "w2"})
	if err := w2.SetAESGCMKeyBytes(w2Key); err != nil {
		t.Fatal(err)
	}

	multi := NewMultiWrapper(w1)
	var encBlob *wrapping.EncryptedBlobInfo

	// Start with one and ensure encrypt/decrypt
	{
		encBlob, err = multi.Encrypt(nil, []byte("foobar"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if encBlob.KeyInfo.KeyID != "w1" {
			t.Fatal(encBlob.KeyInfo.KeyID)
		}
		decVal, err := multi.Decrypt(nil, encBlob, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(decVal) != "foobar" {
			t.Fatal("mismatch in multi")
		}

		decVal, err = w1.Decrypt(nil, encBlob, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(decVal) != "foobar" {
			t.Fatal("mismatch in w1")
		}
	}

	// Rotate the encryptor
	if success := multi.SetEncryptingWrapper(w2); !success {
		t.Fatal("failed to set encrypting wrapper")
	}
	{
		// Verify we can still decrypt the existing blob
		decVal, err := multi.Decrypt(nil, encBlob, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(decVal) != "foobar" {
			t.Fatal("mismatch in multi after rotation")
		}

		// Now encrypt again and decrypt against the new base wrapper
		encBlob, err = multi.Encrypt(nil, []byte("foobar"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if encBlob.KeyInfo.KeyID != "w2" {
			t.Fatal(encBlob.KeyInfo.KeyID)
		}
		decVal, err = multi.Decrypt(nil, encBlob, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(decVal) != "foobar" {
			t.Fatal("mismatch in multi")
		}

		decVal, err = w2.Decrypt(nil, encBlob, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(decVal) != "foobar" {
			t.Fatal("mismatch in w2")
		}
	}

	// Check retriving the wrappers
	checkW1 := multi.WrapperForKeyID("w1")
	if checkW1 == nil {
		t.Fatal("nil w1")
	}
	if checkW1.KeyID() != "w1" {
		t.Fatal("mismatch")
	}
	checkW2 := multi.WrapperForKeyID("w2")
	if checkW2 == nil {
		t.Fatal("nil w2")
	}
	if checkW2.KeyID() != "w2" {
		t.Fatal("mismatch")
	}
	checkW3 := multi.WrapperForKeyID("w3")
	if checkW3 != nil {
		t.Fatal("expected key not found")
	}

	// Check removing a wrapper, and not removing the base wrapper
	multi.RemoveWrapper("w1")
	multi.RemoveWrapper("w2")
	{
		decVal, err := multi.Decrypt(nil, encBlob, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(decVal) != "foobar" {
			t.Fatal("mismatch in multi")
		}

		// Check that w1 is no longer valid
		encBlob, err = w1.Encrypt(nil, []byte("foobar"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if encBlob.KeyInfo.KeyID != "w1" {
			t.Fatal(encBlob.KeyInfo.KeyID)
		}
		decVal, err = multi.Decrypt(nil, encBlob, nil)
		if err != ErrKeyNotFound {
			t.Fatal(err)
		}
	}
}
