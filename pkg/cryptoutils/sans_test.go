// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cryptoutils

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/test"
)

func TestMarshalAndUnmarshalOtherNameSAN(t *testing.T) {
	otherName := "foo!example.com"
	critical := true

	ext, err := MarshalOtherNameSAN(otherName, critical)
	if err != nil {
		t.Fatalf("unexpected error for MarshalOtherNameSAN: %v", err)
	}
	if ext.Critical != critical {
		t.Fatalf("expected extension to be critical")
	}
	if !ext.Id.Equal(SANOID) {
		t.Fatalf("expected extension's OID to be SANs OID")
	}
	// https://lapo.it/asn1js/#MCGgHwYKKwYBBAGDvzABB6ARDA9mb28hZXhhbXBsZS5jb20
	// 30 - Constructed sequence
	// 21 - length of sequence
	// A0 - Context-specific (class 2) (bits 8,7) with Constructed bit (bit 6) and 0 tag
	// 1F - length of context-specific field (OID)
	// 06 - OID tag
	// 0A - length of OID
	// 2B 06 01 04 01 83 BF 30 01 07 - OID
	// A0 - Context-specific (class 2) with Constructed bit and 0 tag
	//      (needed for EXPLICIT encoding, which wraps field in outer encoding)
	// 11 - length of context-specific field (string)
	// 0C - UTF8String tag
	// 0F - length of string
	// 66 6F 6F 21 65 78 61 6D 70 6C 65 2E 63 6F 6D - string
	if hex.EncodeToString(ext.Value) != "3021a01f060a2b0601040183bf300107a0110c0f666f6f216578616d706c652e636f6d" {
		t.Fatalf("unexpected ASN.1 encoding")
	}

	on, err := UnmarshalOtherNameSAN([]pkix.Extension{*ext})
	if err != nil {
		t.Fatalf("unexpected error for UnmarshalOtherNameSAN: %v", err)
	}
	if on != otherName {
		t.Fatalf("unexpected OtherName, expected %s, got %s", otherName, on)
	}
}

func TestUnmarshalOtherNameSANFailures(t *testing.T) {
	var err error

	// failure: no SANs extension
	ext := &pkix.Extension{
		Id:       asn1.ObjectIdentifier{},
		Critical: true,
		Value:    []byte{},
	}
	_, err = UnmarshalOtherNameSAN([]pkix.Extension{*ext})
	if err == nil || !strings.Contains(err.Error(), "no OtherName found") {
		t.Fatalf("expected error finding no OtherName, got %v", err)
	}

	// failure: bad sequence
	ext = &pkix.Extension{
		Id:       SANOID,
		Critical: true,
		Value:    []byte{},
	}
	_, err = UnmarshalOtherNameSAN([]pkix.Extension{*ext})
	if err == nil || !strings.Contains(err.Error(), "sequence truncated") {
		t.Fatalf("expected error with invalid ASN.1, got %v", err)
	}

	// failure: extra data after valid sequence
	b, _ := hex.DecodeString("3021a01f060a2b0601040183bf300107a0110c0f666f6f216578616d706c652e636f6d" + "30")
	ext = &pkix.Extension{
		Id:       SANOID,
		Critical: true,
		Value:    b,
	}
	_, err = UnmarshalOtherNameSAN([]pkix.Extension{*ext})
	if err == nil || !strings.Contains(err.Error(), "trailing data after X.509 extension") {
		t.Fatalf("expected error with extra data, got %v", err)
	}

	// failure: non-universal class (Change last two bits: 30 = 00110000 => 10110000 -> B0)
	b, _ = hex.DecodeString("B021a01f060a2b0601040183bf300107a0110c0f666f6f216578616d706c652e636f6d")
	ext = &pkix.Extension{
		Id:       SANOID,
		Critical: true,
		Value:    b,
	}
	_, err = UnmarshalOtherNameSAN([]pkix.Extension{*ext})
	if err == nil || !strings.Contains(err.Error(), "bad SAN sequence") {
		t.Fatalf("expected error with non-universal class, got %v", err)
	}

	// failure: not compound sequence (Change 6th bit: 30 = 00110000 => 00010000 -> 10)
	b, _ = hex.DecodeString("1021a01f060a2b0601040183bf300107a0110c0f666f6f216578616d706c652e636f6d")
	ext = &pkix.Extension{
		Id:       SANOID,
		Critical: true,
		Value:    b,
	}
	_, err = UnmarshalOtherNameSAN([]pkix.Extension{*ext})
	if err == nil || !strings.Contains(err.Error(), "bad SAN sequence") {
		t.Fatalf("expected error with non-compound sequence, got %v", err)
	}

	// failure: non-sequence tag (Change lower 5 bits: 30 = 00110000 => 00100010 -> 12)
	b, _ = hex.DecodeString("1221a01f060a2b0601040183bf300107a0110c0f666f6f216578616d706c652e636f6d")
	ext = &pkix.Extension{
		Id:       SANOID,
		Critical: true,
		Value:    b,
	}
	_, err = UnmarshalOtherNameSAN([]pkix.Extension{*ext})
	if err == nil || !strings.Contains(err.Error(), "bad SAN sequence") {
		t.Fatalf("expected error with non-sequence tag, got %v", err)
	}

	// failure: no GeneralName with tag=0 (Change lower 5 bits of first sequence field: 3021a01f -> 3021a11f)
	b, _ = hex.DecodeString("3021a11f060a2b0601040183bf300108a0110c0f666f6f216578616d706c652e636f6d")
	ext = &pkix.Extension{
		Id:       SANOID,
		Critical: true,
		Value:    b,
	}
	_, err = UnmarshalOtherNameSAN([]pkix.Extension{*ext})
	if err == nil || !strings.Contains(err.Error(), "no OtherName found") {
		t.Fatalf("expected error with no GeneralName, got %v", err)
	}

	// failure: invalid OtherName (Change tag of UTF8String field to 1: a0110c0f -> a1110c0f)
	b, _ = hex.DecodeString("3021a01f060a2b0601040183bf300108a1110c0f666f6f216578616d706c652e636f6d")
	ext = &pkix.Extension{
		Id:       SANOID,
		Critical: true,
		Value:    b,
	}
	_, err = UnmarshalOtherNameSAN([]pkix.Extension{*ext})
	if err == nil || !strings.Contains(err.Error(), "could not parse requested OtherName SAN") {
		t.Fatalf("expected error with invalid OtherName, got %v", err)
	}

	// failure: OtherName has wrong OID (2b0601040183bf300107 -> 2b0601040183bf300108)
	b, _ = hex.DecodeString("3021a01f060a2b0601040183bf300108a0110c0f666f6f216578616d706c652e636f6d")
	ext = &pkix.Extension{
		Id:       SANOID,
		Critical: true,
		Value:    b,
	}
	_, err = UnmarshalOtherNameSAN([]pkix.Extension{*ext})
	if err == nil || !strings.Contains(err.Error(), "unexpected OID for OtherName") {
		t.Fatalf("expected error with wrong OID, got %v", err)
	}

	// failure: multiple OtherName fields (Increase sequence size from 0x21 -> 0x42, duplicate OtherName)
	b, _ = hex.DecodeString("3042a01f060a2b0601040183bf300107a0110c0f666f6f216578616d706c652e636f6da01f060a2b0601040183bf300107a0110c0f666f6f216578616d706c652e636f6d")
	ext = &pkix.Extension{
		Id:       SANOID,
		Critical: true,
		Value:    b,
	}
	_, err = UnmarshalOtherNameSAN([]pkix.Extension{*ext})
	if err == nil || !strings.Contains(err.Error(), "expected only one OtherName") {
		t.Fatalf("expected error with multiple OtherName fields, got %v", err)
	}
}

func TestGetSubjectAltnernativeNames(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)

	// generate with OtherName, which will override other SANs
	ext, err := MarshalOtherNameSAN("subject-othername", true)
	if err != nil {
		t.Fatalf("error marshalling SANs: %v", err)
	}
	exts := []pkix.Extension{*ext}
	leafCert, _, _ := test.GenerateLeafCert("unused", "oidc-issuer", subCert, subKey, exts...)

	sans := GetSubjectAlternateNames(leafCert)
	if len(sans) != 1 {
		t.Fatalf("expected 1 SAN field, got %d", len(sans))
	}
	if sans[0] != "subject-othername" {
		t.Fatalf("unexpected OtherName SAN value")
	}

	// generate with all other SANs
	leafCert, _, err = test.GenerateLeafCertWithSubjectAlternateNames([]string{"subject-dns.example.com"}, []string{"subject-email@domain.com"}, []net.IP{{1, 2, 3, 4}}, []*url.URL{{Scheme: "https", Path: "testURL"}}, "oidc-issuer", subCert, subKey)
	if err != nil {
		t.Fatalf("unexpected error generating cert: %v", err)
	}
	sans = GetSubjectAlternateNames(leafCert)
	if len(sans) != 4 {
		t.Fatalf("expected 1 SAN field, got %d", len(sans))
	}
	if sans[0] != "subject-dns.example.com" {
		t.Fatalf("unexpected DNS SAN value: %v", sans[0])
	}
	if sans[1] != "subject-email@domain.com" {
		t.Fatalf("unexpected email SAN value: %v", sans[1])
	}
	if sans[2] != "1.2.3.4" {
		t.Fatalf("unexpected IP SAN value: %v", sans[2])
	}
	if sans[3] != "https://testURL" {
		t.Fatalf("unexpected URL SAN value: %v", sans[3])
	}
}
