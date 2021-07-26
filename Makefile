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

.PHONY: all pkg test test-e2e clean lint

all: pkg

GENSRC = pkg/generated/models/%.go pkg/generated/client/%.go
SRCS = $(shell find pkg -iname "*.go"|grep -v pkg/generated) $(GENSRC)

# TODO: pin this reference to the openapi file to a specific fulcio release tag
$(GENSRC):
	swagger generate client -f https://raw.githubusercontent.com/sigstore/fulcio/main/openapi.yaml -r COPYRIGHT.txt -t pkg/generated -P github.com/coreos/go-oidc/v3/oidc.IDToken

lint:
	$(GOBIN)/golangci-lint run -v ./...

pkg:
	go build ./...

test:
	go test ./...

test-e2e:
	go test -tags e2e ./test/e2e/...

clean:
	rm -rf sigstore

