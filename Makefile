.PHONY: all lint test

.EXPORT_ALL_VARIABLES:
GO111MODULE = on

all: lint test

lint:
	golangci-lint run

test:
	go test -race -cover ./...
