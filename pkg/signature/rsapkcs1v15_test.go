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
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// keys defined in rsapss_test.go

func TestRSAPKCS1v15SignerVerifier(t *testing.T) {
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(rsaKey), cryptoutils.SkipPassword)
	if err != nil {
		t.Errorf("unexpected error unmarshalling private key: %v", err)
	}
	sv, err := LoadRSAPKCS1v15SignerVerifier(privateKey.(*rsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Errorf("unexpected error creating signer/verifier: %v", err)
	}

	message := []byte("sign me")
	// created with openssl dgst -sign privKey.pem -sha256
	sig, _ := base64.StdEncoding.DecodeString("AMpSInspjqXdigO0vACd7KMilwLMnrHqnSitnyY0dNiIQ912I2wEme3sMqAMeWnsJ26BxObqV2iMZiggnmeMwd92+6dWpfc2is7m3IbdrUmwKG8y4WDegXEq+EWOy6qsPoqXFPgn1500MFkwrMASP035Gu6wTPmc92zimKozT91j2MNBSONWlcrP89DYBpSVnX+AUs4CKJUppRH/AeyKtftm8GC2TOGrG83U5JqDNegbp5Sji3ViAbUtbiHfob4o1VDGqlyCLgaB0sthekI0XFucWHJj9xRBFazcSBA7Bw1I+T08SqsjfP9Gz43VkItnZbwXMWdSRV81vEK0UuX/rA==")
	testingSigner(t, sv, "rsa", crypto.SHA256, message)
	testingVerifier(t, sv, "rsa", crypto.SHA256, sig, message)

	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pubKey))
	if err != nil {
		t.Errorf("unexpected error unmarshalling public key: %v", err)
	}
	v, err := LoadRSAPKCS1v15Verifier(publicKey.(*rsa.PublicKey), crypto.SHA256)
	if err != nil {
		t.Errorf("unexpected error creating verifier: %v", err)
	}
	testingVerifier(t, v, "rsa", crypto.SHA256, sig, message)
}
