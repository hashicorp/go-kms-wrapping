package plugin

import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	gp "github.com/hashicorp/go-plugin"
)

// wrapper embeds Plugin and is used as the top-level
type wrapper struct {
	gp.Plugin

	impl wrapping.Wrapper
}

func NewWrapper(impl wrapping.Wrapper) *wrapper {
	return &wrapper{
		impl: impl,
	}
}
