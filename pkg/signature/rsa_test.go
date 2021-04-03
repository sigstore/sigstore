/*
Copyright 2021 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signature

import (
	"testing"
)

func newTestRSASignerVerifier(t *testing.T) RSASignerVerifier {
	t.Helper()
	sv, err := NewDefaultRSASignerVerifier()
	if err != nil {
		t.Fatalf("NewDefaultRSASignerVerifier() failed with error: %v", err)
	}
	return sv
}

func TestDefaultRSASignerVerifier(t *testing.T) {
	sv := newTestRSASignerVerifier(t)
	smokeTestSignerVerifier(t, sv)
}
