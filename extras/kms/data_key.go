package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-dbw"
)

//  DataKey represents the DEKs (keys to encrypt data) of the system and must
//  have a parent root key and a purpose.
type DataKey struct {
	// PrivateId is used to access the key
	PrivateId string `json:"private_id,omitempty" gorm:"primary_key"`
	// RootKeyId for the key
	RootKeyId string `json:"root_key_id,omitempty" gorm:"default:null"`
	// Purpose of the the key
	Purpose KeyPurpose `json:"purpose,omitempty" gorm:"default:null"`
	// CreateTime from the RDBMS
	CreateTime time.Time `json:"create_time,omitempty" gorm:"default:current_timestamp"`
}

// NewDataKey creates a new in memory data key.  This key is used for wrapper
// operations.  No options are currently supported.
func NewDataKey(rootKeyId string, purpose KeyPurpose, _ ...Option) (*DataKey, error) {
	const op = "kms.NewDataKey"
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	switch purpose {
	case KeyPurposeUnknown:
		return nil, fmt.Errorf("%s: missing purpose: %w", op, ErrInvalidParameter)
	case KeyPurposeRootKey:
		return nil, fmt.Errorf("%s: cannot be a purpose of %q: %w", op, purpose, ErrInvalidParameter)
	}
	c := &DataKey{
		RootKeyId: rootKeyId,
		Purpose:   purpose,
	}
	return c, nil
}

// Clone creates a clone of the DataKey
func (k *DataKey) Clone() *DataKey {
	return &DataKey{
		PrivateId:  k.PrivateId,
		RootKeyId:  k.RootKeyId,
		Purpose:    k.Purpose,
		CreateTime: k.CreateTime,
	}
}

// VetForWrite validates the key before it's written.
func (k *DataKey) vetForWrite(ctx context.Context, opType dbw.OpType) error {
	const op = "kms.(DataKey).vetForWrite"
	if k.PrivateId == "" {
		return fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	switch opType {
	case dbw.CreateOp:
		if k.RootKeyId == "" {
			return fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
		}
		switch k.Purpose {
		case KeyPurposeUnknown:
			return fmt.Errorf("%s: missing purpose: %w", op, ErrInvalidParameter)
		case KeyPurposeRootKey:
			return fmt.Errorf("%s: cannot be a purpose of %q: %w", op, k.Purpose, ErrInvalidParameter)
		}
	case dbw.UpdateOp:
		return fmt.Errorf("%s: data key is immutable: %w", op, ErrInvalidParameter)
	}
	return nil
}

// TableName returns the tablename
func (k *DataKey) TableName() string { return "kms_data_key" }

// GetPrivateId returns the key's private id
func (k *DataKey) GetPrivateId() string { return k.PrivateId }

// GetRootKeyId returns the key's root key id
func (k *DataKey) GetRootKeyId() string { return k.RootKeyId }
