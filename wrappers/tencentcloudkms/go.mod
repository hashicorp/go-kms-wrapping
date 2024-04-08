module github.com/openbao/go-kms-wrapping/wrappers/tencentcloudkms/v2

go 1.22.1

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/openbao/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common v1.0.604
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/kms v1.0.604
)

require (
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

retract [v2.0.0, v2.0.1]
