# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

proto:
	protoc github.com.hashicorp.go.kms.wrapping.types.proto --go_out=paths=source_relative:.

.PHONY: proto
