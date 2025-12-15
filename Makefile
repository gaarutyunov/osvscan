.PHONY: all build test clean install

all: build

build:
	go build -o cmd/osvscan/osvscan ./cmd/osvscan

test:
	go test -v ./...

install:
	go install ./cmd/osvscan

clean:
	rm -f cmd/osvscan/osvscan
	go clean -cache -testcache

lint:
	golangci-lint run

fmt:
	go fmt ./...

mod:
	go mod tidy
	go mod verify
