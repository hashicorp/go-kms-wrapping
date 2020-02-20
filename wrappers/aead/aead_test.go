package aead

import (
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
