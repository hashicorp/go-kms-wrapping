package aead

import (
	"crypto/rand"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping"
)

func TestShamirVsAEAD(t *testing.T) {
	a := NewWrapper(nil)
	if a.Type() != wrapping.AEAD {
		t.Fatal(a.Type())
	}
	s := NewShamirWrapper(nil)
	if s.Type() != wrapping.Shamir {
		t.Fatal(s.Type())
	}
}

func TestWrapperAndDerivedWrapper(t *testing.T) {
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	root := NewWrapper(nil)
	if err := root.SetAESGCMKeyBytes(rootKey); err != nil {
		t.Fatal(err)
	}
	encBlob, err := root.Encrypt(nil, []byte("foobar"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Sanity check
	decVal, err := root.Decrypt(nil, encBlob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(decVal) != "foobar" {
		t.Fatal("mismatch in root")
	}

	sub, err := root.NewDerivedWrapper(&DerivedWrapperOptions{
		Salt: []byte("zip"),
		Info: []byte("zap"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// This should fail as it should be a different key
	decVal, err = sub.Decrypt(nil, encBlob, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	subEncBlob, err := sub.Encrypt(nil, []byte("foobar"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Sanity check
	subDecVal, err := sub.Decrypt(nil, subEncBlob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(subDecVal) != "foobar" {
		t.Fatal("mismatch in sub")
	}
	// This should fail too
	decVal, err = root.Decrypt(nil, subEncBlob, nil)
	if err == nil {
		t.Fatal("expected error")
	}

	// Ensure that deriving a second subkey with the same params works
	sub2, err := root.NewDerivedWrapper(&DerivedWrapperOptions{
		Salt: []byte("zip"),
		Info: []byte("zap"),
	})
	if err != nil {
		t.Fatal(err)
	}
	subDecVal, err = sub2.Decrypt(nil, subEncBlob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(subDecVal) != "foobar" {
		t.Fatal("mismatch in sub2")
	}

	// Ensure that a subkey with different params doesn't work
	subBad, err := root.NewDerivedWrapper(&DerivedWrapperOptions{
		Salt: []byte("zap"),
		Info: []byte("zip"),
	})
	if err != nil {
		t.Fatal(err)
	}
	subDecVal, err = subBad.Decrypt(nil, subEncBlob, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
}
