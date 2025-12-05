// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package awskms

import (
	"context"
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hashicorp/go-secure-stdlib/awsutil/v2"
)

type mockClient struct {
	KmsApi
	keyId string
}

// Encrypt is a mocked call that returns a base64 encoded string.
func (m *mockClient) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	m.keyId = *input.KeyId

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(input.Plaintext)))
	base64.StdEncoding.Encode(encoded, input.Plaintext)

	return &kms.EncryptOutput{
		CiphertextBlob: encoded,
		KeyId:          input.KeyId,
	}, nil
}

// Decrypt is a mocked call that returns a decoded base64 string.
func (m *mockClient) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	decLen := base64.StdEncoding.DecodedLen(len(input.CiphertextBlob))
	decoded := make([]byte, decLen)
	len, err := base64.StdEncoding.Decode(decoded, input.CiphertextBlob)
	if err != nil {
		return nil, err
	}

	if len < decLen {
		decoded = decoded[:len]
	}

	return &kms.DecryptOutput{
		KeyId:     &m.keyId,
		Plaintext: decoded,
	}, nil
}

// DescribeKey is a mocked call that returns the keyId.
func (m *mockClient) DescribeKey(_ context.Context, inpput *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if m.keyId == "" {
		return nil, &awsutil.MockAWSErr{
			Code:    "ErrCodeNotFoundException",
			Message: "Key not found",
		}

	}

	return &kms.DescribeKeyOutput{
		KeyMetadata: &types.KeyMetadata{
			KeyId: &m.keyId,
		},
	}, nil
}
