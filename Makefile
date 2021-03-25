.PHONY: all test clean lint gosec

all: client

GENSRC = pkg/generated/models/%.go pkg/generated/client/%.go
SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go"|grep -v pkg/generated) $(GENSRC)

$(GENSRC):
	swagger generate client -f https://raw.githubusercontent.com/sigstore/fulcio/development/openapi.yaml -r COPYRIGHT.txt -t pkg/generated -P github.com/coreos/go-oidc/v3/oidc.IDToken

lint:
	$(GOBIN)/golangci-lint run -v ./...

gosec:
	$(GOBIN)/gosec ./...

client: $(SRCS)
	go build

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
