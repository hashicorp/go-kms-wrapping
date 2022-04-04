package kms

// Dek is an interface wrapping dek types to allow a lot less switching in loadDek
type Dek interface {
	GetRootKeyId() string
	GetPrivateId() string
}

// DekVersion is an interface wrapping versioned dek types to allow a lot less switching in loadDek
type DekVersion interface {
	GetPrivateId() string
	GetKey() []byte
}
