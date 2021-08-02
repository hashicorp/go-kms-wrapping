proto:
	protoc github.com.hashicorp.go.kms.wrapping.types.proto --go_out=paths=source_relative:.
	protoc plugin/github.com.hashicorp.go.kms.wrapping.plugin.v1.proto --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:.

.PHONY: proto
