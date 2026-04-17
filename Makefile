BINARY := geogrep
WINDOWS_BINARY := geogrep-windows-amd64.exe
VERSION := $(shell cat VERSION)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X geogrep/internal/geogrep.Version=$(VERSION) -X geogrep/internal/geogrep.Commit=$(COMMIT) -X geogrep/internal/geogrep.BuildDate=$(BUILD_DATE)

.PHONY: all build build-windows test fmt tidy clean version

all: build build-windows

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/geogrep

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(WINDOWS_BINARY) ./cmd/geogrep

test:
	go test ./...

fmt:
	gofmt -w $(shell find cmd internal -name '*.go')

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) $(WINDOWS_BINARY)

version:
	@echo $(VERSION)
