module github.com/openbao/go-kms-wrapping/wrappers/alicloudkms/v2

go 1.22.1

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/aliyun/alibaba-cloud-sdk-go v1.62.301
	github.com/openbao/go-kms-wrapping/v2 v2.2.0
)

require (
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/opentracing/opentracing-go v1.2.1-0.20220228012449-10b1cf09e00b // indirect
	google.golang.org/protobuf v1.36.4 // indirect
	gopkg.in/ini.v1 v1.66.2 // indirect
)

retract [v2.0.0, v2.0.2]
