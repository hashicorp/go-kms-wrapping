// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

import (
	key_manager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

type mockKeyManager struct {
	getKey   func(req *key_manager.GetKeyRequest) (*key_manager.Key, error)
	encrypt  func(req *key_manager.EncryptRequest) (*key_manager.EncryptResponse, error)
	decrypt  func(req *key_manager.DecryptRequest) (*key_manager.DecryptResponse, error)
	lastOpts []scw.RequestOption
}

func (m *mockKeyManager) GetKey(req *key_manager.GetKeyRequest, opts ...scw.RequestOption) (*key_manager.Key, error) {
	m.lastOpts = opts
	if m.getKey != nil {
		return m.getKey(req)
	}
	usage := key_manager.KeyAlgorithmSymmetricEncryptionAes256Gcm
	return &key_manager.Key{
		ID:    req.KeyID,
		State: key_manager.KeyStateEnabled,
		Usage: &key_manager.KeyUsage{
			SymmetricEncryption: &usage,
		},
	}, nil
}

func (m *mockKeyManager) Encrypt(req *key_manager.EncryptRequest, opts ...scw.RequestOption) (*key_manager.EncryptResponse, error) {
	m.lastOpts = opts
	if m.encrypt != nil {
		return m.encrypt(req)
	}
	return &key_manager.EncryptResponse{
		KeyID:      req.KeyID,
		Ciphertext: append([]byte("enc:"), req.Plaintext...),
	}, nil
}

func (m *mockKeyManager) Decrypt(req *key_manager.DecryptRequest, opts ...scw.RequestOption) (*key_manager.DecryptResponse, error) {
	m.lastOpts = opts
	if m.decrypt != nil {
		return m.decrypt(req)
	}
	plaintext := req.Ciphertext
	if len(plaintext) > 4 && string(plaintext[:4]) == "enc:" {
		plaintext = plaintext[4:]
	}
	return &key_manager.DecryptResponse{
		KeyID:     req.KeyID,
		Plaintext: plaintext,
	}, nil
}
