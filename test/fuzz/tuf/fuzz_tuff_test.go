//
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
package tuf

import (
	"testing"

	"github.com/sigstore/sigstore/pkg/tuf"
)

func FuzzTestAddKey(f *testing.F) {
	f.Fuzz(func(t *testing.T, email, issuer string) {
		root := tuf.NewRoot()
		publicKey := tuf.FulcioVerificationKey(email, issuer)
		if !root.AddKey(publicKey) {
			t.Errorf("Adding new key failed")
		}
		if _, ok := root.Keys[publicKey.ID()]; !ok {
			t.Errorf("Error adding public key")
		}
		// Add duplicate key.
		if root.AddKey(publicKey) {
			t.Errorf("Duplicate key should not add to dictionary")
		}
		if len(root.Keys) != 1 {
			t.Errorf("Root keys should contain exactly one key.")
		}
	})
}
