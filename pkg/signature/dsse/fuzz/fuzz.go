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

package fuzz

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	ds "github.com/sigstore/sigstore/pkg/signature/dsse"
)

// Fuzz is the fuzz testing.
func Fuzz(b []byte) int {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	sv, err := signature.LoadECDSASignerVerifier(p, crypto.SHA256)
	if err != nil {
		panic(err)
	}

	data := string(b)
	payloadType := string(b)

	wsv := ds.WrapSignerVerifier(sv, payloadType)

	sig, err := wsv.SignMessage(strings.NewReader(data))
	if err != nil {
		panic(err)
	}

	if err := wsv.VerifySignature(bytes.NewReader(sig), nil); err != nil {
		panic(err)
	}

	env := dsse.Envelope{}
	if err := json.Unmarshal(sig, &env); err != nil {
		panic(err)
	}
	if env.PayloadType != payloadType {
		panic(fmt.Sprintf("Expected payloadType %s, got %s", payloadType, env.PayloadType))
	}

	got, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		panic(err)
	}

	if string(got) != data {
		panic(fmt.Sprintf("Expected payload %s, got %s", data, env.Payload))
	}
	return 1
}
