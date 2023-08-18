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
INTEGRATION_TEST_DIR := ./test/e2e
GO-FUZZ-BUILD := $(TOOLS_BIN_DIR)/go-fuzz-build

GOLANGCI_LINT_DIR = $(shell pwd)/bin
GOLANGCI_LINT_BIN = $(GOLANGCI_LINT_DIR)/golangci-lint

LDFLAGS ?=

golangci-lint:
	rm -f $(GOLANGCI_LINT_BIN) || :
	set -e ;\
	GOBIN=$(GOLANGCI_LINT_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.53.2 ;\

lint: golangci-lint ## Run golangci-lint
	$(GOLANGCI_LINT_BIN) run -v --new-from-rev=HEAD~ ./...

pkg: ## Build pkg
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" ./...

test: ## Run Tests for all Go modules.
	go test ./...
	cd ./pkg/signature/kms/aws && go test ./... && cd -
	cd ./pkg/signature/kms/azure && go test ./... && cd -
	cd ./pkg/signature/kms/gcp && go test ./... && cd -
	cd ./pkg/signature/kms/hashivault && go test ./... && cd -
	cd ./pkg/signature/kms/yckms && go test ./... && cd -

tidy: ## Run go mod tidy all Go modules.
	go mod tidy
	cd ./pkg/signature/kms/aws && go mod tidy && cd -
	cd ./pkg/signature/kms/azure && go mod tidy && cd -
	cd ./pkg/signature/kms/gcp && go mod tidy && cd -
	cd ./pkg/signature/kms/hashivault && go mod tidy && cd -
	cd ./pkg/signature/kms/yckms && go mod tidy && cd -

test-e2e: ## Run E2E Tests
	cd $(INTEGRATION_TEST_DIR); ./e2e-test.sh

fuzz: $(GO-FUZZ-BUILD) ## Run Fuzz tests
	cd $(FUZZ_DIR);$(GO-FUZZ-BUILD) -o pem-fuzz.zip ./pem
	cd $(FUZZ_DIR);$(GO-FUZZ-BUILD) -o signature-fuzz.zip ./signature
	cd $(FUZZ_DIR);$(GO-FUZZ-BUILD) -o fuzz-fuzz.zip .
	cd $(FUZZ_DIR);$(GO-FUZZ-BUILD) -o dsse-fuzz.zip ./dsse

clean: ## Clean workspace
	rm -rf sigstore
	rm -f $(FUZZ_DIR)/*fuzz.zip
	rm -rf $(TOOLS_BIN_DIR)

## --------------------------------------
## Tooling Binaries
## --------------------------------------

$(GO-FUZZ-BUILD): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR);go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/go-fuzz-build github.com/dvyukov/go-fuzz/go-fuzz-build

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
