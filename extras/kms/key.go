package kms

import "time"

type KeyType string

const (
	// KeyTypeDek defines a KEK (key encryption key)
	KeyTypeKek KeyType = "kek"

	// KeyTypeDek defines a DEK (data encryption key)
	KeyTypeDek = "dek"
)

// KeyVersion is a key's version (the construct containing the encryption key itself)
type KeyVersion struct {

	// Id is the key version's id
	Id string `json:"id"`

	// Version is the key version's version
	Version uint `json:"version"`

	// CreateTime is the key version's create time.
	CreateTime time.Time `json:"create_time"`
}

// Key is the permanent construct representing ephemeral key versions
type Key struct {

	// Id is the key's id
	Id string `json:"id"`

	// Scope is the scope of the key
	Scope string `json:"scope"`

	// Type is the key's KeyType.
	Type KeyType `json:"type"`

	// CreateTime is the time this key was created in the db
	CreateTime time.Time `json:"create_time"`

	// Purpose is the key's purpose
	Purpose KeyPurpose `json:"key_purpose"`

	// Versions is a list of key versions belonging to this key
	Versions []*KeyVersion `json:"versions"`
}

func newKeyFromRootKey(key *rootKey) *Key {
	return &Key{
		Id:         key.PrivateId,
		Scope:      key.ScopeId,
		CreateTime: key.CreateTime,
		Type:       KeyTypeKek,
		Purpose:    KeyPurposeRootKey,
	}
}

func newKeyFromDataKey(key *dataKey, scope string) *Key {
	return &Key{
		Id:         key.PrivateId,
		Scope:      scope,
		CreateTime: key.CreateTime,
		Type:       KeyTypeDek,
		Purpose:    key.Purpose,
	}
}

// ScopeKeys is the package containing all keys in use by a certain scope
// including a single root key (KEK) and all data keys (DEKs)
type ScopeKeys struct {

	// RootKey is the scope's root KEK (containing all key versions)
	RootKey *Key `json:"root_key"`

	// DataKeys is a slice of all the DEKs used by the scope (each key containing all key versions)
	DataKeys []*Key `json:"data_keys"`
}
