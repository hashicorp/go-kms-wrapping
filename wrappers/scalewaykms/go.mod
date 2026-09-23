module github.com/hashicorp/go-kms-wrapping/wrappers/scalewaykms/v2

go 1.24.0

replace github.com/hashicorp/go-kms-wrapping/v2 => ../..

require (
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.24
	github.com/scaleway/scaleway-sdk-go v1.0.0-beta.36
)

require (
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.9 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.6 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
