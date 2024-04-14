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

all: pkg

TOOLS_DIR := hack/tools
TOOLS_BIN_DIR := $(abspath $(TOOLS_DIR)/bin)
FUZZ_DIR := ./test/fuzz
INTEGRATION_TEST_DIR := ./test/e2e
GO-FUZZ-BUILD := $(TOOLS_BIN_DIR)/go-fuzz-build
FUZZ_DURATION ?= 10s

GOLANGCI_LINT_DIR = $(shell pwd)/bin
GOLANGCI_LINT_BIN = $(GOLANGCI_LINT_DIR)/golangci-lint

LDFLAGS ?=

GO_MOD_DIRS = . ./pkg/signature/kms/aws ./pkg/signature/kms/azure ./pkg/signature/kms/gcp ./pkg/signature/kms/hashivault

golangci-lint:
	rm -f $(GOLANGCI_LINT_BIN) || :
	set -e ;\
	GOBIN=$(GOLANGCI_LINT_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.53.2 ;\

lint: golangci-lint ## Run golangci-lint
	$(GOLANGCI_LINT_BIN) run -v --new-from-rev=HEAD~ ./...

pkg: ## Build pkg
	set -o xtrace; \
	for dir in $(GO_MOD_DIRS) ; do \
	    cd $$dir && CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" ./... && cd - >/dev/null; \
	done

test: ## Run Tests for all Go modules.
	set -o xtrace; \
	for dir in $(GO_MOD_DIRS) ; do \
	    cd $$dir && go test ./... && cd - >/dev/null; \
	done

tidy: ## Run go mod tidy all Go modules.
	set -o xtrace; \
	for dir in $(GO_MOD_DIRS) ; do \
	    cd $$dir && go mod tidy && cd - >/dev/null; \
	done

test-e2e: ## Run E2E Tests
	cd $(INTEGRATION_TEST_DIR); ./e2e-test.sh

fuzz:
	cd test/fuzz && go test -fuzz FuzzECDSASigner -fuzztime $(FUZZ_DURATION) ./signature
	cd test/fuzz && go test -fuzz FuzzComputeDigest -fuzztime $(FUZZ_DURATION) ./signature
	cd test/fuzz && go test -fuzz FuzzComputeVerifying -fuzztime $(FUZZ_DURATION) ./signature
	cd test/fuzz && go test -fuzz FuzzED25529SignerVerfier -fuzztime $(FUZZ_DURATION) ./signature
	cd test/fuzz && go test -fuzz FuzzRSAPKCS1v15SignerVerfier -fuzztime $(FUZZ_DURATION) ./signature
	cd test/fuzz && go test -fuzz FuzzRSAPSSSignerVerfier -fuzztime $(FUZZ_DURATION) ./signature
	cd test/fuzz && go test -fuzz FuzzDSSE -fuzztime $(FUZZ_DURATION) ./dsse
	cd test/fuzz && go test -fuzz FuzzGetPassword -fuzztime $(FUZZ_DURATION) .
	cd test/fuzz && go test -fuzz FuzzLoadCertificates -fuzztime $(FUZZ_DURATION) ./pem
	cd test/fuzz && go test -fuzz FuzzUnmarshalCertificatesFromPEM -fuzztime $(FUZZ_DURATION) ./pem
	cd test/fuzz && go test -fuzz FuzzUnmarshalPEMToPublicKey -fuzztime $(FUZZ_DURATION) ./pem

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
