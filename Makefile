export GO ?= go
export CGO_ENABLED = 0

TAG := $(shell git describe --always --tags $(git rev-list --tags --max-count=1) --match v*)

.PHONY: all
all: wireproxy

.PHONY: wireproxy
wireproxy:
	${GO} build -trimpath -ldflags "-s -w -X 'main.version=${TAG}'" ./cmd/wireproxy

.PHONY: clean
clean:
	${RM} wireproxy
