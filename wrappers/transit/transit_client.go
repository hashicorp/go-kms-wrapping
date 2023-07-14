// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	vault "github.com/hashicorp/vault/api"
	"path"
)

type TransitClientEncryptor interface {
	Close()
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}

type TransitClient struct {
	vaultClient     *vault.Client
	lifetimeWatcher *vault.Renewer

	mountPath string
	keyName   string
}

func newTransitClient(logger hclog.Logger, opts *options) (*TransitClient, *wrapping.WrapperConfig, error) {
	var err error
	var transitClient *TransitClient

	if transitClient, err = getTransitClient(logger, opts); err != nil {
		return nil, nil, err
	}

	var namespace = getNamespace(opts)
	if namespace != "" {
		transitClient.vaultClient.SetNamespace(namespace)
	}

	var disableRenewal bool
	if disableRenewal, err = getDisableRenewal(opts); err != nil {
		return nil, nil, err
	}

	var roleName = getVaultRoleName(opts)
	if !disableRenewal && transitClient.vaultClient.Token() != "" {
		if err = tokenRenew(transitClient, logger); err != nil {
			return nil, nil, err
		}
	} else if roleName != "" {
		if err = performK8sAuthentication(transitClient, roleName, opts, logger); err != nil {
			return nil, nil, err
		}
	}

	var wrapConfig = newWrapConfig(transitClient, namespace)

	return transitClient, wrapConfig, nil
}

func (c *TransitClient) Close() {
	if c.lifetimeWatcher != nil {
		c.lifetimeWatcher.Stop()
	}
}

func (c *TransitClient) Encrypt(plaintext []byte) ([]byte, error) {
	encPlaintext := base64.StdEncoding.EncodeToString(plaintext)
	encryptPath := path.Join(c.mountPath, "encrypt", c.keyName)
	secret, err := c.vaultClient.Logical().Write(encryptPath, map[string]interface{}{
		"plaintext": encPlaintext,
	})
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("after encrypt operation the returned secret from vault is nil")
	}
	if secret.Data == nil {
		return nil, errors.New("after encrypt operation no data was found in returned secret from vault")
	}
	ct := secret.Data["ciphertext"]
	if ct == nil {
		return nil, errors.New("after encrypt operation ciphertext was not found in data returned from vault")
	}
	ctStr, ok := ct.(string)
	if !ok {
		return nil, errors.New("after encrypt operation ciphertext in data returned from vault is not a string")
	}

	return []byte(ctStr), nil
}

func (c *TransitClient) Decrypt(ciphertext []byte) ([]byte, error) {
	decryptPath := path.Join(c.mountPath, "decrypt", c.keyName)
	secret, err := c.vaultClient.Logical().Write(decryptPath, map[string]interface{}{
		"ciphertext": string(ciphertext),
	})
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("after decrypt operation the returned secret from vault is nil")
	}
	if secret.Data == nil {
		return nil, errors.New("after decrypt operation no data was found in returned secret from vault")
	}
	pt := secret.Data["plaintext"]
	if pt == nil {
		return nil, errors.New("after decrypt operation plaintext was not found in data returned from vault")
	}
	ptStr, ok := pt.(string)
	if !ok {
		return nil, errors.New("after decrypt operation plaintext in data returned from vault is not a string")
	}

	plaintext, err := base64.StdEncoding.DecodeString(ptStr)
	if err != nil {
		return nil, fmt.Errorf("error base64-decoding plaintext: %w", err)
	}
	return plaintext, nil
}

func (c *TransitClient) GetMountPath() string {
	return c.mountPath
}

func (c *TransitClient) GetApiClient() *vault.Client {
	return c.vaultClient
}
