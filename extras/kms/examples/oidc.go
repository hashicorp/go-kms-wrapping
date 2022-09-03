package examples

import "time"

// OIDC represents the client info for an oidc conn
type OIDC struct {
	// PrivateId is used to access the root key
	PrivateId string `json:"private_id,omitempty" gorm:"primary_key"`
	// ClientId is the oidc client id
	ClientId string `json:"client_id,omitempty"`
	// CtClientSecret is the ciphertext of the client_secret
	CtClientSecret []byte `json:"-" gorm:"column:client_secret" wrapping:"ct,client_secret"`
	// ClientSecret is the oidc client secret (plaintext)
	ClientSecret string `json:"client_secret,omitempty" wrapping:"pt,client_secret"`
	// KeyVersionId is the wrapper key version id used to encrypt/decrypt the client secret
	KeyVersionId string `json:"key_id,omitempty" gorm:"not_null"`
	// CreateTime from the db
	CreateTime time.Time `json:"create_time,omitempty" gorm:"default:current_timestamp"`
}

func (_ *OIDC) TableName() string { return "oidc" }
