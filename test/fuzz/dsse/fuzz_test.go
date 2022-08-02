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

package dsse

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	ds "github.com/sigstore/sigstore/pkg/signature/dsse"
)

func FuzzDSSE(f *testing.F) {
	f.Fuzz(func(t *testing.T, data, payload string) {
		if !utf8.Valid([]byte(data)) {
			t.Skip("invalid utf8")
		}
		if !utf8.Valid([]byte(payload)) {
			t.Skip("invalid utf8")
		}
		p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Errorf("failed to generate key: %v", err)
		}

		sv, err := signature.LoadECDSASignerVerifier(p, crypto.SHA256)
		if err != nil {
			t.Errorf("failed to load signer verifier: %v", err)
		}

		wsv := ds.WrapSignerVerifier(sv, payload)

		sig, err := wsv.SignMessage(strings.NewReader(data))
		if err != nil {
			t.Errorf("failed to sign message: %v", err)
		}

		if err := wsv.VerifySignature(bytes.NewReader(sig), nil); err != nil {
			t.Errorf("failed to verify signature: %v", err)
		}

		env := dsse.Envelope{}
		if err := json.Unmarshal(sig, &env); err != nil {
			panic(err)
		}
		if env.PayloadType != payload {
			t.Errorf("Expected payloadType %s, got %s", payload, env.PayloadType)
		}

		got, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			t.Errorf("failed to decode payload: %v", err)
		}

		if string(got) != data {
			t.Errorf("Expected payload %s, got %s", data, env.Payload)
		}
	})
}
