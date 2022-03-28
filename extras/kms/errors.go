package kms

import "errors"

var (
	// ErrInvalidVersion represents a runtime error when the database version
	// doesn't match the require version of the module.
	ErrInvalidVersion = errors.New("invalid version")

	// ErrInvalidParameter represents and invalid parameter error condition.
	ErrInvalidParameter = errors.New("invalid parameter")

	// ErrMultipleRecords represents multiple records were affected when only
	// one was expected
	ErrMultipleRecords = errors.New("multiple records")

	// ErrRecordNotFound represents that no record was found
	ErrRecordNotFound = errors.New("record not found")
)
