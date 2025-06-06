// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package static

import (
	"context"
	"crypto/rand"
	"io"
	"reflect"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func TestStaticWrapper_Lifecycle(t *testing.T) {
	// Set up wrapper
	s := NewWrapper()

	s.currentKeyId = "test-key"
	s.currentKey = make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, s.currentKey)
	if err != nil {
		t.Fatalf("err=%v", err)
	}

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := s.Decrypt(context.Background(), swi)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}

	kid, err := s.KeyId(context.Background())
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if kid != s.currentKeyId {
		t.Fatalf("key id does not match: expected %s, got %s", s.currentKeyId, kid)
	}

	// Ensure it works with AAD.
	aad := []byte("testing-aad")
	opts := wrapping.WithAad(aad)

	swi, err = s.Encrypt(context.Background(), input, opts)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err = s.Decrypt(context.Background(), swi)
	if err == nil {
		t.Fatal("expected decryption failure without AAD")
	}
	pt, err = s.Decrypt(context.Background(), swi, opts)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}

	// Now test to make sure we can decrypt using the previous key.
	s.previousKeyId = s.currentKeyId
	s.previousKey = s.currentKey

	s.currentKeyId = "test-key-2"
	s.currentKey = make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, s.currentKey)
	if err != nil {
		t.Fatalf("err=%v", err)
	}

	// Decryption of the swi should succeed.
	pt, err = s.Decrypt(context.Background(), swi, opts)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}

	// Removing previous key should cause it to fail.
	s.previousKeyId = ""
	s.previousKey = nil

	pt, err = s.Decrypt(context.Background(), swi, opts)
	if err == nil {
		t.Fatal("expected err failing to decrypt")
	}
}
