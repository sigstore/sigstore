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

package rekorpubs

import (
	"strings"
	"sync"
	"testing"
)

func resetForTests() {
	rekorOnce = new(sync.Once)
}

func TestGetRekorPubs(t *testing.T) {
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)

	rekorPubs, err := GetRekorPubs()
	defer resetForTests()
	if err != nil {
		t.Fatal(err)
	}

	if len(rekorPubs) == 0 {
		t.Error("expected non-empty rekor public keys")
	}

	for rekorLogID, rekorPub := range rekorPubs {
		logID, err := GetLogID(rekorPub.PubKey)
		if err != nil {
			t.Fatalf("error getting log id %s", err)
		}
		if !strings.EqualFold(rekorLogID, logID) {
			t.Fatalf("log id does not match public key, expected %s, got %s", logID, rekorLogID)
		}
	}
}
