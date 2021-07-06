# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

proto:
	protoc github.com.hashicorp.go.kms.wrapping.types.proto --go_out=paths=source_relative:.
	protoc plugin/v1/github.com.hashicorp.go.kms.wrapping.plugin.v1.proto --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:.

.PHONY: proto
