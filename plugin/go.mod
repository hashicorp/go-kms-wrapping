module github.com/hashicorp/go-kms-wrapping/plugin/v2

go 1.16

require (
	github.com/hashicorp/go-hclog v1.1.0
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.0-20220216195002-4ed2d8ce64e2
	github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2 v2.0.0-20220215203045-88be2f269a2a
	github.com/hashicorp/go-plugin v1.4.3
	github.com/stretchr/testify v1.7.0
	google.golang.org/grpc v1.44.0
	google.golang.org/protobuf v1.27.1
)
