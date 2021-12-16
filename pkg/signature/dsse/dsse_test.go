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

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
)

func TestRoundTrip(t *testing.T) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sv, err := signature.LoadECDSASignerVerifier(p, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	data := "sometestdata"
	payloadType := "foo"

	wsv := WrapSignerVerifier(sv, payloadType)

	sig, err := wsv.SignMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if err := wsv.VerifySignature(bytes.NewReader(sig), nil); err != nil {
		t.Fatal(err)
	}

	env := dsse.Envelope{}
	if err := json.Unmarshal(sig, &env); err != nil {
		t.Fatal(err)
	}
	if env.PayloadType != payloadType {
		t.Errorf("Expected payloadType %s, got %s", payloadType, env.PayloadType)
	}

	got, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != data {
		t.Errorf("Expected payload %s, got %s", data, env.Payload)
	}
}

func TestMultiRoundTrip(t *testing.T) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sv, err := signature.LoadECDSASignerVerifier(p, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	p2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sv2, err := signature.LoadECDSASignerVerifier(p2, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	data := "sometestdata"
	payloadType := "foo"

	wsv := WrapMultiSignerVerifier(payloadType, 2, sv, sv2)

	sig, err := wsv.SignMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if err := wsv.VerifySignature(bytes.NewReader(sig), nil); err != nil {
		t.Fatal(err)
	}

	env := dsse.Envelope{}
	if err := json.Unmarshal(sig, &env); err != nil {
		t.Fatal(err)
	}
	if env.PayloadType != payloadType {
		t.Errorf("Expected payloadType %s, got %s", payloadType, env.PayloadType)
	}

	got, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != data {
		t.Errorf("Expected payload %s, got %s", data, env.Payload)
	}
}

func TestInvalidThresholdMultiRoundTrip(t *testing.T) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sv, err := signature.LoadECDSASignerVerifier(p, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	p2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sv2, err := signature.LoadECDSASignerVerifier(p2, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	data := "sometestdata"
	payloadType := "foo"

	ws := WrapMultiSigner(payloadType, sv, sv2)

	sig, err := ws.SignMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	wv := WrapMultiVerifier(payloadType, 2, sv)

	if err := wv.VerifySignature(bytes.NewReader(sig), nil); err == nil {
		t.Fatalf("Did not fail verification on bogus signature")
	}

}

func TestInvalidSignature(t *testing.T) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	v, err := signature.LoadECDSAVerifier(&p.PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	wv := WrapVerifier(v)
	sig := []byte("not valid JSON")

	if err := wv.VerifySignature(bytes.NewReader(sig), nil); err == nil {
		t.Fatalf("Did not fail verification on bogus signature")
	}
}
