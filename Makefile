proto:
	buf lint
	buf generate
	buf format -w
	
.PHONY: proto
