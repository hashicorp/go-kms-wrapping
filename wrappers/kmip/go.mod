module github.com/openbao/go-kms-wrapping/wrappers/kmip/v2

go 1.23.1

toolchain go1.23.6

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/hashicorp/go-uuid v1.0.3
	github.com/openbao/go-kms-wrapping/v2 v2.3.0
	github.com/ovh/kmip-go v0.3.3
)

require (
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.9 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
)

retract [v2.0.0, v2.0.2]
