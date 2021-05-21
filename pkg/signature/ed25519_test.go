//
// Copyright 2021 The Sigstore Authors.
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

import "testing"

func newTestED25519SignerVerifier(t *testing.T) ED25519SignerVerifier {
	t.Helper()
	sv, err := NewDefaultED25519SignerVerifier()
	if err != nil {
		t.Fatalf("NewDefaultED25519SignerVerifier() failed with error: %v", err)
	}
	return sv
}

func TestDefaultED25519SignerVerifier(t *testing.T) {
	sv := newTestED25519SignerVerifier(t)
	smokeTestSignerVerifier(t, sv)
}
