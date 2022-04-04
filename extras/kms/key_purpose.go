package kms

// KeyPurpose allows an application to specify the reason they need a key; this
// is used to select which DEK to return
type KeyPurpose string

const (
	// KeyPurposeUnknown is the default, and indicates that a correct purpose
	// wasn't specified
	KeyPurposeUnknown KeyPurpose = ""

	// KeyPurposeRootKey defines a root key purpose
	KeyPurposeRootKey = "rootKey"
)

func reservedKeyPurpose() []string {
	return []string{
		string(KeyPurposeRootKey),
	}
}
