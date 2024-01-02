module github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2

go 1.20

replace github.com/hashicorp/go-kms-wrapping/v2 => ../..

require (
	github.com/aws/aws-sdk-go v1.44.210
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.9-0.20230228100945-740d2999c798
	github.com/hashicorp/go-secure-stdlib/awsutil v0.1.6
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7
	github.com/stretchr/testify v1.8.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/color v1.14.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.1 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
