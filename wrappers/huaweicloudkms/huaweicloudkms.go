// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package huaweicloudkms

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/hashicorp/go-cleanhttp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/huaweicloud/golangsdk"
	huaweisdk "github.com/huaweicloud/golangsdk/openstack"
	kmsKeys "github.com/huaweicloud/golangsdk/openstack/kms/v1/keys"
)

// These constants contain the accepted env vars; the Vault one is for backwards compat
const (
	EnvHuaweiCloudKmsWrapperKeyId = "HUAWEICLOUDKMS_WRAPPER_KEY_ID"
)

// Wrapper is a Wrapper that uses HuaweiCloud's KMS
type Wrapper struct {
	client       kmsClient
	keyId        string
	currentKeyId *atomic.Value
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new HuaweiCloud Wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

// SetConfig sets the fields on the HuaweiCloudKmsWrapper object based on
// values from the config parameter.
//
// Order of precedence HuaweiCloud values:
// * Environment variable
// * Value from Vault configuration file
// * Instance metadata role (access key and secret key)
func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Check and set KeyId
	keyId, err := getConfig(
		"kms_key_id",
		os.Getenv(EnvHuaweiCloudKmsWrapperKeyId),
		opts.WithKeyId)
	if err != nil {
		return nil, err
	}
	k.keyId = keyId

	if k.client == nil {
		client, err := buildKMSClient(opts)
		if err != nil {
			return nil, err
		}
		k.client = client
	}

	// Test the client connection using provided key ID
	keyInfo, err := k.client.describeKey(k.keyId)
	if err != nil {
		return nil, fmt.Errorf("error fetching HuaweiCloud KMS key information: %w", err)
	}

	// Store the current key id. If using a key alias, this will point to the actual
	// unique key that that was used for this encrypt operation.
	k.currentKeyId.Store(keyInfo.KeyID)

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["region"] = k.client.getRegion()
	wrapConfig.Metadata["project"] = k.client.getProject()
	wrapConfig.Metadata["kms_key_id"] = k.keyId

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeHuaweiCloudKms, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the the HuaweiCloud CMK.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	output, err := k.client.encrypt(k.keyId, base64.StdEncoding.EncodeToString(env.Key))
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	// Store the current key id.
	keyID := output.KeyId
	k.currentKeyId.Store(keyID)

	return &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      keyID,
			WrappedKey: []byte(output.Ciphertext),
		},
	}, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	// KeyId is not passed to this call because HuaweiCloud handles this
	// internally based on the metadata stored with the encrypted data
	plainText, err := k.client.decrypt(string(in.KeyInfo.WrappedKey))
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(plainText)
	if err != nil {
		return nil, err
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        keyBytes,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	pt, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return pt, nil
}

func getConfig(name string, values ...string) (string, error) {
	for _, v := range values {
		if "" != v {
			return v, nil
		}
	}

	return "", fmt.Errorf("'%s' not found for HuaweiCloud kms wrapper configuration", name)
}

func buildKMSClient(opts *options) (kmsClient, error) {
	// Check and set region.
	region, err := getConfig("region", os.Getenv("HUAWEICLOUD_REGION"), opts.withRegion)
	if err != nil {
		return nil, err
	}

	// Check and set project.
	project, err := getConfig("project", os.Getenv("HUAWEICLOUD_PROJECT"), opts.withProject)
	if err != nil {
		return nil, err
	}

	// Check and set access key.
	accessKey, err := getConfig("access_key", os.Getenv("HUAWEICLOUD_ACCESS_KEY"), opts.withAccessKey)
	if err != nil {
		return nil, err
	}

	// Check and set project.
	secretKey, err := getConfig("secret_key", os.Getenv("HUAWEICLOUD_SECRET_KEY"), opts.withSecretKey)
	if err != nil {
		return nil, err
	}

	// Check and set endpoint.
	endpoint, _ := getConfig(
		"identity_endpoint",
		os.Getenv("HUAWEICLOUD_IDENTITY_ENDPOINT"),
		opts.withIdentityEndpoint,
	)

	option := golangsdk.AKSKAuthOptions{
		Region:           region,
		ProjectName:      project,
		AccessKey:        accessKey,
		SecretKey:        secretKey,
		IdentityEndpoint: endpoint,
	}

	client, err := buildServiceClient(option)
	if err != nil {
		return nil, err
	}

	return &kmsClientImpl{region: region, project: project, client: client}, nil
}

func buildServiceClient(option golangsdk.AKSKAuthOptions) (*golangsdk.ServiceClient, error) {
	client, err := huaweisdk.NewClient(option.IdentityEndpoint)
	if err != nil {
		return nil, err
	}

	transport := cleanhttp.DefaultTransport()
	transport.TLSClientConfig = &tls.Config{}
	client.HTTPClient.Transport = transport

	err = huaweisdk.Authenticate(client, option)
	if err != nil {
		return nil, err
	}

	return huaweisdk.NewKMSV1(client, golangsdk.EndpointOpts{
		Region:       option.Region,
		Availability: golangsdk.AvailabilityPublic,
	})
}

type encryptResponse struct {
	KeyId      string `json:"key_id"`
	Ciphertext string `json:"cipher_text"`
}

type kmsClient interface {
	getRegion() string
	getProject() string
	describeKey(keyID string) (*kmsKeys.Key, error)
	encrypt(keyID, plainText string) (encryptResponse, error)
	decrypt(cipherText string) (string, error)
}

type kmsClientImpl struct {
	region  string
	project string
	client  *golangsdk.ServiceClient
}

func (c *kmsClientImpl) getRegion() string {
	return c.region
}

func (c *kmsClientImpl) getProject() string {
	return c.project
}

func (c *kmsClientImpl) describeKey(keyID string) (*kmsKeys.Key, error) {
	return kmsKeys.Get(c.client, keyID).ExtractKeyInfo()
}

func (c *kmsClientImpl) encrypt(keyID, plainText string) (encryptResponse, error) {
	url := c.client.ServiceURL(c.client.ProjectID, "kms", "encrypt-data")
	r := golangsdk.Result{}
	_, r.Err = c.client.Post(
		url,
		&map[string]interface{}{"key_id": keyID, "plain_text": plainText},
		&r.Body,
		&golangsdk.RequestOpts{
			OkCodes:     []int{200},
			MoreHeaders: map[string]string{"Content-Type": "application/json"},
		})

	resp := encryptResponse{}
	err := r.ExtractInto(&resp)
	if err != nil {
		return resp, fmt.Errorf("error encrypting data: %s", err)
	}
	return resp, nil
}

func (c *kmsClientImpl) decrypt(cipherText string) (string, error) {
	url := c.client.ServiceURL(c.client.ProjectID, "kms", "decrypt-data")
	r := golangsdk.Result{}
	_, r.Err = c.client.Post(
		url,
		&map[string]interface{}{"cipher_text": cipherText},
		&r.Body,
		&golangsdk.RequestOpts{
			OkCodes:     []int{200},
			MoreHeaders: map[string]string{"Content-Type": "application/json"},
		})

	var resp struct {
		PlainText string `json:"plain_text"`
	}
	err := r.ExtractInto(&resp)
	if err != nil {
		return "", fmt.Errorf("error decrypting data: %s", err)
	}

	return resp.PlainText, nil
}
