test:
	go test ./... $(TESTARGS)
	cd entropy && go test ./... $(TESTARGS)
	cd plugin && go test ./... $(TESTARGS)
	cd wrappers/aead && go test ./...  $(TESTARGS)
	cd wrappers/alicloudkms && go test ./... $(TESTARGS)
	cd wrappers/awskms && go test ./... $(TESTARGS)
	cd wrappers/azurekeyvault && go test ./... $(TESTARGS)
	cd wrappers/gcpckms && go test ./... $(TESTARGS)
	cd wrappers/huaweicloudkms && go test ./... $(TESTARGS)
	cd wrappers/kmip && go test ./... $(TESTARGS)
	cd wrappers/ocikms && go test ./... $(TESTARGS)
	cd wrappers/pkcs11 && go test ./... $(TESTARGS)
	cd wrappers/static && go test ./... $(TESTARGS)
	cd wrappers/tencentcloudkms && go test ./... $(TESTARGS)
	cd wrappers/transit && go test ./... $(TESTARGS)

.PHONY: proto
proto:
	find . -type f -name "*.pb.go" -delete
	buf generate
	buf format -w

	# inject classification tags (see: https://github.com/hashicorp/go-eventlogger/tree/main/filters/encrypt)
	@protoc-go-inject-tag -input=./github.com.openbao.go.kms.wrapping.v2.types.pb.go

.PHONY: tools
tools:
	go install github.com/favadi/protoc-go-inject-tag@v1.4.0
	go install github.com/bufbuild/buf/cmd/buf@v1.15.1

.PHONY: tidy-all
tidy-all:
	cd entropy && go mod tidy
	cd examples/plugin-cli && go mod tidy
	cd examples/plugin-cli/plugins/mains/transit && go mod tidy
	cd plugin && go mod tidy
	cd wrappers/aead && go mod tidy
	cd wrappers/alicloudkms && go mod tidy
	cd wrappers/awskms && go mod tidy
	cd wrappers/azurekeyvault && go mod tidy
	cd wrappers/gcpckms && go mod tidy
	cd wrappers/huaweicloudkms && go mod tidy
	cd wrappers/kmip && go mod tidy
	cd wrappers/ocikms && go mod tidy
	cd wrappers/tencentcloudkms && go mod tidy
	cd wrappers/static && go mod tidy
	cd wrappers/transit && go mod tidy
	go mod tidy

.PHONY: generate-all
generate-all:
	cd entropy && GOARCH= GOOS= go generate ./...
	cd plugin && GOARCH= GOOS= go generate ./...
	cd wrappers/aead && GOARCH= GOOS= go generate ./...
	cd wrappers/alicloudkms && GOARCH= GOOS= go generate ./...
	cd wrappers/awskms && GOARCH= GOOS= go generate ./...
	cd wrappers/azurekeyvault && GOARCH= GOOS= go generate ./...
	cd wrappers/gcpckms && GOARCH= GOOS= go generate ./...
	cd wrappers/huaweicloudkms && GOARCH= GOOS= go generate ./...
	cd wrappers/kmip && GOARCH= GOOS= go generate ./...
	cd wrappers/ocikms && GOARCH= GOOS= go generate ./...
	cd wrappers/pkcs11 && GOARCH= GOOS= go generate ./...
	cd wrappers/static && GOARCH= GOOS= go generate ./...
	cd wrappers/tencentcloudkms && GOARCH= GOOS= go generate ./...
	cd wrappers/transit && GOARCH= GOOS= go generate ./...
	GOARCH= GOOS= go generate ./...

.PHONY: fmt
fmt:
	find . -name '*.go' | grep -v pb.go | grep -v vendor | xargs go run mvdan.cc/gofumpt@latest -w
