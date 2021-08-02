PLUGIN_TMP_DIR := $(shell mktemp -d)

test-plugin:
	go build -o "${PLUGIN_TMP_DIR}/plugin" plugin/main.go
	PLUGIN_TMP_DIR=${PLUGIN_TMP_DIR} go test -v -run TestPluginWrapper

.PHONY: test-plugin
