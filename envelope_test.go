package wrapping

import (
	"bytes"
	"testing"
)

func TestEnvelope(t *testing.T) {
	input := []byte("test")
	env, err := NewEnvelope(nil).Encrypt(input, nil)
	if err != nil {
		t.Fatal(err)
	}

	output, err := NewEnvelope(nil).Decrypt(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(input, output) {
		t.Fatalf("expected the same text: expected %s, got %s", string(input), string(output))
	}
}

func TestEnvelopeAAD(t *testing.T) {
	input := []byte("test")
	env, err := NewEnvelope(nil).Encrypt(input, []byte("foo"))
	if err != nil {
		t.Fatal(err)
	}

	output, err := NewEnvelope(nil).Decrypt(env, nil)
	if err == nil {
		t.Fatal("expected an error")
	}

	output, err = NewEnvelope(nil).Decrypt(env, []byte("foo"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(input, output) {
		t.Fatalf("expected the same text: expected %s, got %s", string(input), string(output))
	}
}
