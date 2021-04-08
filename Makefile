.PHONY: all test clean lint gosec

all: client

GENSRC = pkg/generated/models/%.go pkg/generated/client/%.go
SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go"|grep -v pkg/generated) $(GENSRC)

# Set version variables for LDFLAGS
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

PKG=github.com/sigstore/sigstore/cmd
LDFLAGS="-X $(PKG).gitVersion=$(GIT_VERSION) -X $(PKG).gitCommit=$(GIT_HASH) -X $(PKG).gitTreeState=$(GIT_TREESTATE) -X $(PKG).buildDate=$(BUILD_DATE)"

$(GENSRC):
	swagger generate client -f https://raw.githubusercontent.com/sigstore/fulcio/development/openapi.yaml -r COPYRIGHT.txt -t pkg/generated -P github.com/coreos/go-oidc/v3/oidc.IDToken

lint:
	$(GOBIN)/golangci-lint run -v ./...

gosec:
	$(GOBIN)/gosec ./...

client: #$(SRCS)
	CGO_ENABLED=0 go build -ldflags $(LDFLAGS) -o sigstore

test:
	go test ./...

clean:
	rm -rf sigstore

#up:
	#docker-compose -f docker-compose.yml build
	#docker-compose -f docker-compose.yml up

#debug:
	#docker-compose -f docker-compose.yml -f docker-compose.debug.yml build fulcio-server-debug
	#docker-compose -f docker-compose.yml -f docker-compose.debug.yml up fulcio-server-debug
