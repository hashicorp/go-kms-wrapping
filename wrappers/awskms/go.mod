module github.com/openbao/go-kms-wrapping/wrappers/awskms/v2

go 1.22.1

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/aws/aws-sdk-go v1.44.210
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/go-secure-stdlib/awsutil v0.3.0
	github.com/openbao/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.8.4
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/color v1.14.1 // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract [v2.0.0, v2.0.8]
