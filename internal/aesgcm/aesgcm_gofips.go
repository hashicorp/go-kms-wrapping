// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

//go:build gofips

// This tag selects native Go FIPS behavior. Keep it distinct from the generic
// "fips" tag, which is also used by BoringCrypto builds.
package aesgcm

import (
	"crypto/cipher"
	"fmt"
	"io"
)

const nonceSize = 12

func New(block cipher.Block) (cipher.AEAD, error) {
	return cipher.NewGCMWithRandomNonce(block)
}

func Seal(aead cipher.AEAD, plaintext, nonce, additionalData []byte, randomReader io.Reader) ([]byte, []byte, error) {
	if aead.NonceSize() != 0 {
		return nil, nil, fmt.Errorf("AEAD does not use Go-managed nonces in the gofips build")
	}
	if nonce != nil {
		return nil, nil, fmt.Errorf("explicit IV is not supported by the gofips build")
	}
	if randomReader != nil {
		return nil, nil, fmt.Errorf("random reader option is not supported by the gofips build")
	}
	sealed := aead.Seal(nil, nil, plaintext, additionalData)
	if len(sealed) < nonceSize {
		return nil, nil, fmt.Errorf("invalid sealed ciphertext length %d", len(sealed))
	}
	return sealed[:nonceSize], sealed[nonceSize:], nil
}

func SealBlob(aead cipher.AEAD, plaintext, nonce, additionalData []byte, randomReader io.Reader) ([]byte, error) {
	nonce, ciphertext, err := Seal(aead, plaintext, nonce, additionalData, randomReader)
	if err != nil {
		return nil, err
	}
	return append(nonce, ciphertext...), nil
}

func Open(aead cipher.AEAD, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if aead.NonceSize() != 0 {
		return nil, fmt.Errorf("AEAD does not use Go-managed nonces in the gofips build")
	}
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("invalid IV length %d, AEAD requires %d bytes", len(nonce), nonceSize)
	}
	sealed := make([]byte, 0, len(nonce)+len(ciphertext))
	sealed = append(sealed, nonce...)
	sealed = append(sealed, ciphertext...)
	return aead.Open(nil, nil, sealed, additionalData)
}

func OpenBlob(aead cipher.AEAD, blob, additionalData []byte) ([]byte, error) {
	if len(blob) < nonceSize {
		return nil, fmt.Errorf("invalid ciphertext length %d, must be at least %d bytes", len(blob), nonceSize)
	}
	return Open(aead, blob[:nonceSize], blob[nonceSize:], additionalData)
}
