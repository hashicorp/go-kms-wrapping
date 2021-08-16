PLUGIN_TMP_DIR := $(shell mktemp -d)

test-plugin:
	go build -o "${PLUGIN_TMP_DIR}/plugin" testplugin/main.go
	PLUGIN_PATH="${PLUGIN_TMP_DIR}/plugin" go test -v -run TestAeadPluginWrapper

.PHONY: test-plugin
