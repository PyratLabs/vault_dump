BINARY = vault_dump
OUT_DIR = build

VERSION=$(shell git describe --tags --always --dirty)
COMMIT=$(shell git rev-parse HEAD)

LDFLAGS = -ldflags "-X main.version=${VERSION} -X main.gitHash=${COMMIT}"

all: clean linux windows darwin

linux:
	for GOARCH in 386 arm amd64 arm64 ; do \
		GOOS=linux GOARCH=$${GOARCH} go build ${LDFLAGS} -o ${OUT_DIR}/${BINARY}-linux-$${GOARCH} . ; \
	done

windows:
	for GOARCH in 386 arm amd64 ; do \
		GOOS=windows GOARCH=$${GOARCH} go build ${LDFLAGS} -o ${OUT_DIR}/${BINARY}-windows-$${GOARCH}.exe . ; \
	done

darwin:
	for GOARCH in amd64 arm64 ; do \
		GOOS=darwin GOARCH=$${GOARCH} go build ${LDFLAGS} -o ${OUT_DIR}/${BINARY}-darwin-$${GOARCH} . ; \
	done

clean:
	-rm -f ${OUT_DIR}/${BINARY}-*

.PHONY: linux windows darwin
