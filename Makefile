export GO ?= go

.PHONY: all
all: wireproxy

.PHONY: wireproxy
wireproxy:
	tag="$$(git describe --tag 2>/dev/null)" && \
	${GO} build -ldflags "-X 'main.version=$$tag'" ./cmd/wireproxy

.PHONY: clean
clean:
	${RM} wireproxy
