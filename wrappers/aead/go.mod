module github.com/openbao/go-kms-wrapping/wrappers/aead/v2

go 1.22.1

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require github.com/openbao/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	google.golang.org/protobuf v1.36.4 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract [v2.0.0, v2.0.8]
