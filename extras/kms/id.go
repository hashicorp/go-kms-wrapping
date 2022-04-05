package kms

import (
	"fmt"

	"github.com/hashicorp/go-dbw"
)

const (
	// RootKeyPrefix is a prefix used with RootKey IDs
	RootKeyPrefix = "krk"
	// RootKeyVersionPrefix is a prefix used with RootKeyVersion IDs
	RootKeyVersionPrefix = "krkv"
	// DataKeyPrefix is a prefix used with RootKey IDs
	DataKeyPrefix = "kdk"
	// DataKeyVersionPrefix is a prefix used with DataKeyVersion IDs
	DataKeyVersionPrefix = "kdkv"
)

func newRootKeyId() (string, error) {
	const op = "kms.newRootKeyId"
	id, err := dbw.NewId(RootKeyPrefix)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}

func newRootKeyVersionId() (string, error) {
	const op = "kms.newRootKeyVersionId"
	id, err := dbw.NewId(RootKeyVersionPrefix)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}

func newDataKeyId() (string, error) {
	const op = "kms.newDataKeyId"
	id, err := dbw.NewId(DataKeyPrefix)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}

func newDataKeyVersionId() (string, error) {
	const op = "kms.newDataKeyVersionId"
	id, err := dbw.NewId(DataKeyVersionPrefix)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}
