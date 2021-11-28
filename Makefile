#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: all pkg test test-e2e clean lint fuzz help

all: pkg fuzz

TOOLS_DIR := hack/tools
TOOLS_BIN_DIR := $(abspath $(TOOLS_DIR)/bin)
FUZZ_DIR := ./test/fuzz
GO-FUZZ-BUILD := $(TOOLS_BIN_DIR)/go-fuzz-build
GENSRC = pkg/generated/models/%.go pkg/generated/client/%.go
SRCS = $(shell find pkg -iname "*.go"|grep -v pkg/generated) $(GENSRC)

LDFLAGS ?=

# TODO: pin this reference to the openapi file to a specific fulcio release tag
$(GENSRC): $(SWAGGER) ## Build openapi spec
	$(SWAGGER) generate client -f https://raw.githubusercontent.com/sigstore/fulcio/main/openapi.yaml -r COPYRIGHT.txt -t pkg/generated -P github.com/coreos/go-oidc/v3/oidc.IDToken

lint: ## Run golangci-lint
	$(GOBIN)/golangci-lint run -v --new-from-rev=HEAD~ ./...

pkg: ## Build pkg
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" ./...

test: ## Run Tests
	go test ./...

test-e2e: ## Run E2E Tests
	go test -tags e2e ./test/e2e/...

fuzz: $(GO-FUZZ-BUILD) ## Run Fuzz tests
	cd $(FUZZ_DIR);$(GO-FUZZ-BUILD) -o pem-fuzz.zip ./pem 
	cd $(FUZZ_DIR);$(GO-FUZZ-BUILD) -o signature-fuzz.zip ./signature
	cd $(FUZZ_DIR);$(GO-FUZZ-BUILD) -o fuzz-fuzz.zip . 


clean: ## Clean workspace
	rm -rf sigstore
	rm $(FUZZ_DIR)/*fuzz.zip
	rm -rf $(TOOLS_BIN_DIR)

## --------------------------------------
## Tooling Binaries
## --------------------------------------

$(GO-FUZZ-BUILD): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR);go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/go-fuzz-build github.com/dvyukov/go-fuzz/go-fuzz-build

$(SWAGGER): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/swagger github.com/go-swagger/go-swagger/cmd/swagger

##################
# help
##################

help:  ## Display this help
	@awk \
		-v "col=${COLOR}" -v "nocol=${NOCOLOR}" \
		' \
			BEGIN { \
				FS = ":.*##" ; \
				printf "\nUsage:\n  make %s<target>%s\n", col, nocol \
			} \
			/^[a-zA-Z_-]+:.*?##/ { \
				printf "  %s%-15s%s %s\n", col, $$1, nocol, $$2 \
			} \
			/^##@/ { \
				printf "\n%s%s%s\n", col, substr($$0, 5), nocol \
			} \
		' $(MAKEFILE_LIST)
