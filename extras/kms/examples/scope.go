// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package examples

import "time"

// Scope represents an application scope like "global" or some unique id for an
// org or proj.
type Scope struct {
	// PrivateId is used to access the root key
	PrivateId string `json:"private_id,omitempty" gorm:"primary_key"`
	// CreateTime from the db
	CreateTime time.Time `json:"create_time,omitempty" gorm:"default:current_timestamp"`
}

func (_ *Scope) TableName() string { return "scope" }
