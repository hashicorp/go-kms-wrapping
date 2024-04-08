module github.com/openbao/go-kms-wrapping/wrappers/alicloudkms/v2

go 1.22.1

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.1499
	github.com/openbao/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000
)

require (
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jmespath/go-jmespath v0.3.0 // indirect
	github.com/json-iterator/go v1.1.9 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/ini.v1 v1.66.2 // indirect
)

retract [v2.0.0, v2.0.2]
