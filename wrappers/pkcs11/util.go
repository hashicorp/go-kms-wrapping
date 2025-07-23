package pkcs11

import (
	"fmt"
	"strings"
)

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
