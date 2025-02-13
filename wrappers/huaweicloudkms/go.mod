module github.com/openbao/go-kms-wrapping/wrappers/huaweicloudkms/v2

go 1.22.1

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/huaweicloud/golangsdk v0.0.0-20210831081626-d823fe11ceba
	github.com/openbao/go-kms-wrapping/v2 v2.2.0
)

require (
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.9 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.6 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	google.golang.org/protobuf v1.36.4 // indirect
)

retract [v2.0.0, v2.0.1]
