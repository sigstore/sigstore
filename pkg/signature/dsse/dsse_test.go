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

func TestRoundTripWithDecodedPayload(t *testing.T) {
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

	ws := WrapSigner(sv, payloadType)
	sig, err := ws.SignMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	var decoded []byte
	wv := WrapVerifier(sv, WithDecodedPayload(&decoded))
	if err := wv.VerifySignature(bytes.NewReader(sig), nil); err != nil {
		t.Fatal(err)
	}

	if string(decoded) != data {
		t.Errorf("Expected decoded payload %q, got %q", data, string(decoded))
	}
}

func TestMultiRoundTripWithDecodedPayload(t *testing.T) {
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

	wsv := WrapMultiSignerVerifierWithOpts(payloadType, 2, []signature.SignerVerifier{sv, sv2})
	sig, err := wsv.SignMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	var decoded []byte
	wv := WrapMultiVerifierWithOpts(payloadType, 2, []signature.Verifier{sv, sv2}, WithDecodedPayload(&decoded))
	if err := wv.VerifySignature(bytes.NewReader(sig), nil); err != nil {
		t.Fatal(err)
	}

	if string(decoded) != data {
		t.Errorf("Expected decoded payload %q, got %q", data, string(decoded))
	}
}

func TestExpectedPayloadTypeMatch(t *testing.T) {
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

	ws := WrapSigner(sv, payloadType)
	sig, err := ws.SignMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	wv := WrapVerifier(sv, WithExpectedPayloadType("foo"))
	if err := wv.VerifySignature(bytes.NewReader(sig), nil); err != nil {
		t.Fatalf("expected verification to pass with matching payload type: %v", err)
	}
}

func TestExpectedPayloadTypeMismatch(t *testing.T) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sv, err := signature.LoadECDSASignerVerifier(p, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	data := "sometestdata"

	ws := WrapSigner(sv, "foo")
	sig, err := ws.SignMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	wv := WrapVerifier(sv, WithExpectedPayloadType("bar"))
	err = wv.VerifySignature(bytes.NewReader(sig), nil)
	if err == nil {
		t.Fatal("expected verification to fail with mismatched payload type")
	}
	if !strings.Contains(err.Error(), "unexpected payload type") {
		t.Fatalf("expected payload type mismatch error, got: %v", err)
	}
}

func TestSignerVerifierEnforcesPayloadType(t *testing.T) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sv, err := signature.LoadECDSASignerVerifier(p, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	data := "sometestdata"

	// Sign with payloadType "foo"
	ws := WrapSigner(sv, "foo")
	sig, err := ws.SignMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	// WrapSignerVerifier with payloadType "bar" should reject the envelope
	wsv := WrapSignerVerifier(sv, "bar")
	err = wsv.VerifySignature(bytes.NewReader(sig), nil)
	if err == nil {
		t.Fatal("expected verification to fail when SignerVerifier payloadType mismatches envelope")
	}
	if !strings.Contains(err.Error(), "unexpected payload type") {
		t.Fatalf("expected payload type mismatch error, got: %v", err)
	}
}

func TestMultiExpectedPayloadTypeMismatch(t *testing.T) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sv, err := signature.LoadECDSASignerVerifier(p, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	data := "sometestdata"

	ws := WrapMultiSigner("foo", sv)
	sig, err := ws.SignMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	wv := WrapMultiVerifierWithOpts("foo", 1, []signature.Verifier{sv}, WithExpectedPayloadType("bar"))
	err = wv.VerifySignature(bytes.NewReader(sig), nil)
	if err == nil {
		t.Fatal("expected verification to fail with mismatched payload type")
	}
	if !strings.Contains(err.Error(), "unexpected payload type") {
		t.Fatalf("expected payload type mismatch error, got: %v", err)
	}
}

func TestMultiSignerVerifierEnforcesPayloadType(t *testing.T) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sv, err := signature.LoadECDSASignerVerifier(p, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	data := "sometestdata"

	// Sign with payloadType "foo"
	ws := WrapMultiSigner("foo", sv)
	sig, err := ws.SignMessage(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	// WrapMultiSignerVerifier with payloadType "bar" should reject the envelope
	wsv := WrapMultiSignerVerifierWithOpts("bar", 1, []signature.SignerVerifier{sv})
	err = wsv.VerifySignature(bytes.NewReader(sig), nil)
	if err == nil {
		t.Fatal("expected verification to fail when MultiSignerVerifier payloadType mismatches envelope")
	}
	if !strings.Contains(err.Error(), "unexpected payload type") {
		t.Fatalf("expected payload type mismatch error, got: %v", err)
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
