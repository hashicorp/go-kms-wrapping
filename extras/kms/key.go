package kms

import "time"

type KeyType string

const (
	// KeyTypeDek defines a KEK (key encryption key)
	KeyTypeKek KeyType = "kek"

	// KeyTypeDek defines a DEK (data encryption key)
	KeyTypeDek = "dek"
)

// Key is a key
type Key struct {

	// Id is the key's id
	Id string `json:"id"`

	// Scope is the scope of the key
	Scope string `json:"scope"`

	// Type is the key's KeyType.
	Type KeyType `json:"type"`

	// Version is the key's version
	Version uint `json:"version"`

	// CreateTime is the key's create time.
	CreateTime time.Time `json:"create_time"`

	// Purpose is the key's purpose
	Purpose KeyPurpose `json:"key_purpose"`
}
