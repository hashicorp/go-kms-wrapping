package pkcs11

import (
	"crypto"
	"fmt"
	"strconv"
	"strings"

	pkcs11 "github.com/miekg/pkcs11"
)

const DefaultRSAOAEPHash = pkcs11.CKM_SHA256

func parseBool(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("failed to parse boolean value: %s", value)
	}
}

// mechanismFromString parses supported mechanisms from a string.
func mechanismFromString(input string) (uint, uint, error) {
	upper := strings.ToUpper(input)
	switch upper {
	case "CKM_AES_GCM", "AES_GCM":
		return pkcs11.CKM_AES_GCM, pkcs11.CKK_AES, nil
	case "CKM_RSA_PKCS_OAEP", "RSA_PKCS_OAEP":
		return pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKK_RSA, nil
	// Deprecated mechanisms
	case "CKM_AES_CBC_PAD", "AES_CBC_PAD", "CKM_RSA_PKCS", "RSA_PKCS":
		return 0, 0, fmt.Errorf("deprecated mechanism: %s", upper)
	}

	var err error
	var id uint64

	if strings.HasPrefix(input, "0x") {
		id, err = strconv.ParseUint(input[2:], 16, 32)
	} else {
		id, err = strconv.ParseUint(input, 10, 32)
	}

	if err != nil {
		return 0, 0, fmt.Errorf("unsupported mechanism: %s", input)
	}

	switch uint(id) {
	case pkcs11.CKM_AES_GCM:
		return pkcs11.CKM_AES_GCM, pkcs11.CKK_AES, nil
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKK_RSA, nil
	case pkcs11.CKM_AES_CBC, pkcs11.CKM_AES_CBC_PAD, pkcs11.CKM_RSA_PKCS:
		return 0, 0, fmt.Errorf("deprecated mechanism: %s", upper)
	default:
		return 0, 0, fmt.Errorf("unsupported mechanism: %s", input)
	}
}

// hashMechanismToCrypto converts a PKCS#11 hash mechanism to the crypto.Hash equivalent.
func hashMechanismToCrypto(mech uint) crypto.Hash {
	switch mech {
	case pkcs11.CKM_SHA_1:
		return crypto.SHA1
	case pkcs11.CKM_SHA224:
		return crypto.SHA224
	case pkcs11.CKM_SHA256:
		return crypto.SHA256
	case pkcs11.CKM_SHA384:
		return crypto.SHA384
	case pkcs11.CKM_SHA512:
		return crypto.SHA512
	default:
		// Unreachable, only called on previously resolved hash mechanism.
		panic("internal error: unknown hash mechanism")
	}
}

func RsaHashMechFromString(mech string) (uint, uint, error) {
	mech = strings.ToLower(mech)
	switch mech {
	case "sha1":
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil
	case "sha224":
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, nil
	case "sha256":
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, nil
	case "sha384":
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, nil
	case "sha512":
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, nil
	default:
		return 0, 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

// hashMechanismFromStringOrDefault calls RsaHashMechFromString,
// but returns DefaultRSAOAEPHash if the input is empty.
func hashMechanismFromStringOrDefault(input string) (uint, error) {
	switch input {
	case "":
		return DefaultRSAOAEPHash, nil
	default:
		hash, _, err := RsaHashMechFromString(input)
		return hash, err
	}
}
