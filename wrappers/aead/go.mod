module github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2

go 1.13

replace github.com/hashicorp/go-kms-wrapping/v2 => ../..

require (
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000
	github.com/hashicorp/go-uuid v1.0.2
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e
)
