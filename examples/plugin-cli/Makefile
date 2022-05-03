# build the required plugins, so they can be embedded into the service
.PHONY: plugins
plugins:
	@echo "==> Building plugins"
	sh -c "'$(CURDIR)/scripts/plugins.sh'"

# build the cli (including the required plugins)
.PHONY: build
build: plugins
	go build 
