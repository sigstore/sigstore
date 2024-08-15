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

package pem

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func FuzzLoadCertificates(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		b, _ := pem.Decode(data)
		if b == nil {
			t.Skip("invalid pem")
		}

		result, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(data))
		if err != nil {
			if result != nil {
				t.Errorf("result %v should be nil when there is an error %v", result, err)
			}
			t.Skip("invalid pem")
		}
		for _, cert := range result {
			if len(cert.Raw) == 0 {
				t.Errorf("x509 cert raw is empty")
			}
		}
	})
}

func FuzzUnmarshalCertificatesFromPEM(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		b, _ := pem.Decode(data)
		if b == nil {
			t.Skip("invalid pem")
		}
		result, err := cryptoutils.UnmarshalCertificatesFromPEM(data)
		if err != nil {
			if result != nil {
				t.Errorf("result %v should be nil when there is an error %v", result, err)
			}
			t.Skip("invalid pem")
		}
		for _, cert := range result {
			if len(cert.Raw) == 0 {
				t.Errorf("x509 cert raw is empty")
			}
		}
	})
}

func FuzzUnmarshalPEMToPublicKey(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		b, _ := pem.Decode(data)
		if b == nil {
			t.Skip("invalid pem")
		}
		result, err := cryptoutils.UnmarshalPEMToPublicKey(data)
		if err != nil {
			if result != nil {
				t.Errorf("result %v should be nil when there is an error %v", result, err)
			}
			t.Skip("invalid pem")
		}
		if result == nil {
			t.Errorf("result %v should not be nil", result)
		}
	})
}

func FuzzCertificate(f *testing.F) {
	f.Fuzz(func(t *testing.T, withLimited bool, pemBytes []byte, iterations int) {
		var certs []*x509.Certificate
		var err error
		if withLimited {
			certs, err = cryptoutils.UnmarshalCertificatesFromPEMLimited(pemBytes, iterations)
			if err != nil {
				return
			}
			cryptoutils.MarshalCertificatesToPEM(certs)
		} else {
			certs, err = cryptoutils.UnmarshalCertificatesFromPEM(pemBytes)
			if err != nil {
				return
			}
			cryptoutils.MarshalCertificatesToPEM(certs)
		}
		for _, cert := range certs {
			cryptoutils.GetSubjectAlternateNames(cert)
		}
	})
}

func FuzzPrivateKey(f *testing.F) {
	f.Fuzz(func(t *testing.T, pemBytes, password []byte) {
		passFunc := cryptoutils.StaticPasswordFunc(password)
		privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey(pemBytes, passFunc)
		if err != nil {
			return
		}

		cryptoutils.MarshalPrivateKeyToPEM(privateKey)
		cryptoutils.MarshalPrivateKeyToEncryptedDER(privateKey, passFunc)
	})
}

func FuzzPublicKey(f *testing.F) {
	f.Fuzz(func(t *testing.T, firstKeyBytes, secondKeyBytes []byte) {
		first, err := cryptoutils.UnmarshalPEMToPublicKey(firstKeyBytes)
		if err != nil {
			return
		}
		err = cryptoutils.ValidatePubKey(first)
		if err != nil {
			return
		}
		second, err := cryptoutils.UnmarshalPEMToPublicKey(secondKeyBytes)
		if err != nil {
			return
		}
		err = cryptoutils.ValidatePubKey(first)
		if err != nil {
			return
		}
		cryptoutils.EqualKeys(first, second)
		cryptoutils.MarshalPublicKeyToPEM(first)
		cryptoutils.MarshalPublicKeyToPEM(second)
		cryptoutils.SKID(first)
		cryptoutils.SKID(second)
	})
}

func FuzzUnmarshalOtherNameSAN(f *testing.F) {
	f.Fuzz(func(t *testing.T, value []byte) {
		exts := []pkix.Extension{
			pkix.Extension{
				Id:    cryptoutils.SANOID,
				Value: value,
			},
		}
		cryptoutils.UnmarshalOtherNameSAN(exts)
	})
}

func FuzzMarshalUnmarshalOtherNameSAN(f *testing.F) {
	f.Fuzz(func(t *testing.T, name string, critical bool) {
		ext, err := cryptoutils.MarshalOtherNameSAN(name, critical)
		if err != nil {
			return
		}
		exts := []pkix.Extension{*ext}
		cryptoutils.UnmarshalOtherNameSAN(exts)
	})
}
