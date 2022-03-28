package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-dbw"
)

type DataKey struct {
	// PrivateId is used to access the key
	PrivateId string `json:"private_id,omitempty" gorm:"primary_key"`
	// RootKeyId for the key
	RootKeyId string `json:"root_key_id,omitempty" gorm:"default:null"`
	// Purpose of the the key
	Purpose string `json:"purpose,omitempty" gorm:"default:null"`
	// CreateTime from the RDBMS
	CreateTime time.Time `json:"create_time,omitempty" gorm:"default:current_timestamp"`
}

// NewDataKey creates a new in memory data key.  This key is used for wrapper
// operations.  No options are currently supported.
func NewDataKey(rootKeyId, purpose string, _ ...Option) (*DataKey, error) {
	const op = "kms.NewDataKey"
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	if purpose == "" {
		return nil, fmt.Errorf("%s: missing purpose: %w", op, ErrInvalidParameter)
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
func (k *DataKey) vetForWrite(ctx context.Context, r dbw.Reader, opType dbw.OpType) error {
	const op = "kms.(DataKey).VetForWrite"
	if k.PrivateId == "" {
		return fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	switch opType {
	case dbw.CreateOp:
		if k.RootKeyId == "" {
			return fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
		}
	case dbw.UpdateOp:
		return fmt.Errorf("%s: key is immutable: %w", op, ErrInvalidParameter)
	}
	return nil
}

// TableName returns the tablename
func (k *DataKey) TableName() string { return "kms_data_key" }
