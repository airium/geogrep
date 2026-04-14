BINARY := geogrep
VERSION := $(shell cat VERSION)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X geogrep/internal/geogrep.Version=$(VERSION) -X geogrep/internal/geogrep.Commit=$(COMMIT) -X geogrep/internal/geogrep.BuildDate=$(BUILD_DATE)

.PHONY: all build test fmt tidy clean version

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/geogrep

test:
	go test ./...

fmt:
	gofmt -w $(shell find cmd internal -name '*.go')

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)

version:
	@echo $(VERSION)
