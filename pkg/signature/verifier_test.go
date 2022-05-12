// Copyright 2022 The Sigstore Authors.
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

package signature

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestLoadUnsafeVerifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected error generating key: %v", err)
	}
	verifier, err := LoadUnsafeVerifier(key.Public())
	if err != nil {
		t.Fatalf("unexpected error loading verifier: %v", err)
	}
	pubKey, _ := verifier.PublicKey()
	if !key.PublicKey.Equal(pubKey) {
		t.Fatalf("public keys were not equal")
	}
}
