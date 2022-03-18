package kms

import "time"

// Schema represents the current schema in the database
type Schema struct {
	// Version of the schema
	Version string
	// UpdateTime is the last update of the version
	UpdateTime time.Time
	// CreateTime is the create time of the initial version
	CreateTime time.Time
}

// TableName defines the table name for the Version type
func (v *Schema) TableName() string { return "kms_version" }
