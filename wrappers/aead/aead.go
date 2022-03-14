package aead

import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	baseaead "github.com/hashicorp/go-kms-wrapping/v2/aead"
)

type (
	Wrapper       = baseaead.Wrapper
	ShamirWrapper = baseaead.ShamirWrapper
)

var (
	NewWrapper       func() *Wrapper                         = baseaead.NewWrapper
	NewShamirWrapper func() *ShamirWrapper                   = baseaead.NewShamirWrapper
	WithAeadType     func(wrapping.AeadType) wrapping.Option = baseaead.WithAeadType
	WithHashType     func(wrapping.HashType) wrapping.Option = baseaead.WithHashType
	WithInfo         func([]byte) wrapping.Option            = baseaead.WithInfo
	WithKey          func([]byte) wrapping.Option            = baseaead.WithKey
	WithSalt         func([]byte) wrapping.Option            = baseaead.WithSalt
)

// Ensure that we are implementing Wrapper
var (
	_ wrapping.Wrapper = (*Wrapper)(nil)
	_ wrapping.Wrapper = (*ShamirWrapper)(nil)
)
