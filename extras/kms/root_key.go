package kms

import (
	"fmt"
	"time"
)

// RootKey represents the KEKs (keys to encrypt keys) of the system.
type RootKey struct {
	// PrivateId is used to access the root key
	PrivateId string `json:"private_id,omitempty" gorm:"primary_key"`
	// ScopeId for the root key
	ScopeId string `json:"scope_id,omitempty" gorm:"default:null"`
	// CreateTime from the db
	CreateTime time.Time `json:"create_time,omitempty" gorm:"default:current_timestamp"`
}

// NewRootKey creates a new in memory root key. No optionsare currently
// supported.
func NewRootKey(scopeId string, _ ...Option) (*RootKey, error) {
	const op = "kms.NewRootKey"
	if scopeId == "" {
		return nil, fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	c := &RootKey{
		ScopeId: scopeId,
	}
	return c, nil
}

// TableName returns the tablename
func (k *RootKey) TableName() string { return "kms_root_key" }

// Clone creates a clone of the RootKeyVersion
func (k *RootKey) Clone() *RootKey {
	return &RootKey{
		PrivateId:  k.PrivateId,
		ScopeId:    k.ScopeId,
		CreateTime: k.CreateTime,
	}
}

// GetPrivateId returns the key's private id
func (k *RootKey) GetPrivateId() string { return k.PrivateId }
