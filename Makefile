proto:
	find . -type f -name "*.pb.go" -delete
	buf lint
	buf generate
	buf format -w
	
	# inject classification tags (see: https://github.com/hashicorp/go-eventlogger/tree/main/filters/encrypt)
	@protoc-go-inject-tag -input=./github.com.hashicorp.go.kms.wrapping.v2.types.pb.go
	
.PHONY: proto


.PHONY: tools
tools: 
	go generate -tags tools tools/tools.go
	go install github.com/bufbuild/buf/cmd/buf@v1.15.1