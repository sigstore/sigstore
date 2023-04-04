//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dsse

import (
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// TestImplementDSSESigner doesn't functionally test anything, but will fail to compile if the interface is not implemented
func TestImplementsDSSESigner(t *testing.T) {
	var _ dsse.Signer = &SignerAdapter{}
}

// TestImplementDSSEVerifier doesn't functionally test anything, but will fail to compile if the interface is not implemented
func TestImplementsDSSEVerifier(t *testing.T) {
	var _ dsse.Verifier = &VerifierAdapter{}
}
