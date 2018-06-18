.PHONY: lint

lint:
	golangci-lint run --enable-all
