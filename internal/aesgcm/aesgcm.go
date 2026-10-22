// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build !gofips

package aesgcm

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

func New(block cipher.Block) (cipher.AEAD, error) {
	return cipher.NewGCM(block)
}

func Seal(aead cipher.AEAD, plaintext, nonce, additionalData []byte, randomReader io.Reader) ([]byte, []byte, error) {
	if aead.NonceSize() == 0 {
		return nil, nil, errors.New("AEAD with internally generated nonces requires the gofips build")
	}
	if randomReader == nil {
		randomReader = rand.Reader
	}
	if nonce != nil {
		if len(nonce) != aead.NonceSize() {
			return nil, nil, fmt.Errorf("invalid IV length %d, AEAD requires %d bytes", len(nonce), aead.NonceSize())
		}
		nonce = append([]byte(nil), nonce...)
	} else {
		nonce = make([]byte, aead.NonceSize())
		n, err := randomReader.Read(nonce)
		if err != nil {
			return nil, nil, err
		}
		if n != len(nonce) {
			return nil, nil, fmt.Errorf("expected to read %d bytes for iv, got %d", len(nonce), n)
		}
	}
	return nonce, aead.Seal(nil, nonce, plaintext, additionalData), nil
}

func SealBlob(aead cipher.AEAD, plaintext, nonce, additionalData []byte, randomReader io.Reader) ([]byte, error) {
	nonce, ciphertext, err := Seal(aead, plaintext, nonce, additionalData, randomReader)
	if err != nil {
		return nil, err
	}
	return append(nonce, ciphertext...), nil
}

func Open(aead cipher.AEAD, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if aead.NonceSize() == 0 {
		return nil, errors.New("AEAD with internally generated nonces requires the gofips build")
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid IV length %d, AEAD requires %d bytes", len(nonce), aead.NonceSize())
	}
	return aead.Open(nil, nonce, ciphertext, additionalData)
}

func OpenBlob(aead cipher.AEAD, blob, additionalData []byte) ([]byte, error) {
	nonceSize := aead.NonceSize()
	if len(blob) < nonceSize {
		return nil, fmt.Errorf("invalid ciphertext length %d, must be at least %d bytes", len(blob), nonceSize)
	}
	return Open(aead, blob[:nonceSize], blob[nonceSize:], additionalData)
}
