package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
)

type DataKeyVersion struct {
	// PrivateId is used to access the key version
	PrivateId string `json:"private_id,omitempty" gorm:"primary_key"`
	// DataKeyId for the key version
	DataKeyId string `json:"data_key_id,omitempty" gorm:"default:null"`
	// RootKeyVersionId of the version of the root key data.
	RootKeyVersionId string `json:"root_key_version_id,omitempty" gorm:"default:null"`
	// Key is the plain-text of the key data.  we are NOT storing this plain-text key
	// in the db.
	Key []byte `json:"key,omitempty" gorm:"-" wrapping:"pt,key_data"`
	//  CtKey is the ciphertext key data stored in the database
	CtKey []byte `json:"ct_key,omitempty" gorm:"column:key;not_null" wrapping:"ct,key_data"`
	// Version of the key data.  This is not used for optimistic locking, since
	// key versions are immutable.  It's just the version of the key.
	Version uint32 `json:"version,omitempty" gorm:"default:null"`
	// CreateTime from the RDBMS
	CreateTime time.Time `json:"create_time,omitempty" gorm:"default:current_timestamp"`
}

// NewDataKeyVersion creates a new in memory data key version. No options
// are currently supported.
func NewDataKeyVersion(dataKeyId string, key []byte, rootKeyVersionId string, _ ...Option) (*DataKeyVersion, error) {
	const op = "kms.NewDataKeyVersion"
	if dataKeyId == "" {
		return nil, fmt.Errorf("%s: missing data key id: %w", op, ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("%s: missing key: %w", op, ErrInvalidParameter)
	}
	if rootKeyVersionId == "" {
		return nil, fmt.Errorf("%s: missing root key version id: %w", op, ErrInvalidParameter)
	}

	k := &DataKeyVersion{
		DataKeyId:        dataKeyId,
		RootKeyVersionId: rootKeyVersionId,
		Key:              key,
	}
	return k, nil
}

// Clone creates a clone of the OidcKeyVersion
func (k *DataKeyVersion) Clone() *DataKeyVersion {
	clone := &DataKeyVersion{
		PrivateId:  k.PrivateId,
		DataKeyId:  k.DataKeyId,
		CreateTime: k.CreateTime,
	}
	clone.Key = make([]byte, len(k.Key))
	copy(clone.Key, k.Key)

	clone.CtKey = make([]byte, len(k.CtKey))
	copy(clone.CtKey, k.CtKey)
	return clone
}

// vetForWrite validates the data key version before it's written.
func (k *DataKeyVersion) vetForWrite(ctx context.Context, r dbw.Reader, opType dbw.OpType) error {
	const op = "kms.(DataKeyVersion).vetForWrite"
	if k.PrivateId == "" {
		return fmt.Errorf("%s: private id: %w", op, ErrInvalidParameter)
	}
	switch opType {
	case dbw.CreateOp:
		if k.CtKey == nil {
			return fmt.Errorf("%s: missing key: %w", op, ErrInvalidParameter)
		}
		if k.DataKeyId == "" {
			return fmt.Errorf("%s: missing oidc key id: %w", op, ErrInvalidParameter)
		}
		if k.RootKeyVersionId == "" {
			return fmt.Errorf("%s: missing root key version id: %w", op, ErrInvalidParameter)
		}
	case dbw.UpdateOp:
		return fmt.Errorf("%s: key is immutable: %w", op, ErrInvalidParameter)
	}
	return nil
}

// TableName returns the tablename
func (k *DataKeyVersion) TableName() string { return "kms_data_key_version" }

// Encrypt will encrypt the data key version's key
func (k *DataKeyVersion) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(DataKeyVersion).Encrypt"
	if err := structwrapping.WrapStruct(ctx, cipher, k, nil); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Decrypt will decrypt the data key version's key
func (k *DataKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(DataKeyVersion).Decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, k, nil); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}
