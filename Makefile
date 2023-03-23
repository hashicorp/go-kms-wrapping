proto:
	find . -type f -name "*.pb.go" -delete
	buf lint
	buf generate
	buf format -w
	
.PHONY: proto
