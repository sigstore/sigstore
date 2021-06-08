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

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/option"
)

func smokeTestSignerVerifier(t *testing.T, sv SignerVerifier) {
	t.Helper()
	ctx := context.Background()
	pub, err := sv.PublicKey(option.WithContext(ctx))
	if err != nil {
		t.Fatalf("PublicKey() failed with error: %v", err)
	}
	if pub == nil {
		t.Fatal("PublicKey() returned nil")
	}
	payload := []byte("test payload " + fmt.Sprint(rand.Int()))
	sig, err := sv.Sign(bytes.NewReader(payload), option.WithContext(ctx))
	if err != nil {
		t.Fatalf("Sign() failed with error: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign() didn't return a signature")
	}
	if err := sv.Verify(bytes.NewReader(payload), sig, option.WithContext(ctx)); err != nil {
		t.Fatalf("Verify() failed with error: %v", err)
	}
}
