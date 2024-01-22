module github.com/openbao/go-kms-wrapping/plugin/v2

go 1.20

replace github.com/openbao/go-kms-wrapping/v2 => ../

require (
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.15
	github.com/hashicorp/go-plugin v1.5.2
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.2
	github.com/openbao/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.8.4
	google.golang.org/grpc v1.59.0
	google.golang.org/protobuf v1.31.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/color v1.14.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.6.1 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230822172742-b8732ec3820d // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
