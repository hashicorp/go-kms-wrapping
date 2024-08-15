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
	cd wrappers/ocikms && go test ./... $(TESTARGS)
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
