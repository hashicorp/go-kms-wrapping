package kms

import (
	"strings"
)

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

// RemoveDuplicatePurposes will de-dup a set of key purposes
func RemoveDuplicatePurposes(purposes []KeyPurpose) []KeyPurpose {
	purposesMap := make(map[KeyPurpose]struct{}, len(purposes))
	for _, purpose := range purposes {
		purpose = KeyPurpose(strings.TrimSpace(string(purpose)))
		if purpose == "" {
			continue
		}
		purposesMap[purpose] = struct{}{}
	}
	purposes = make([]KeyPurpose, 0, len(purposesMap))
	for purpose := range purposesMap {
		purposes = append(purposes, purpose)
	}
	return purposes
}

func purposeListContains(haystack []KeyPurpose, needle KeyPurpose) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}
