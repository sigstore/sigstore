//go:build gofuzz
// +build gofuzz
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

package pem

import (
	"bytes"
	"encoding/pem"
	"fmt"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func FuzzLoadCertificates(data []byte) int {
	b, _ := pem.Decode(data)
	if b == nil {
		return 0
	}

	result, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(data))
	if err != nil {
		if result != nil {
			panic(fmt.Sprintf("result %v should be nil when there is an error %v", result, err))
		}
		return 0
	}
	for _, cert := range result {
		if len(cert.Raw) == 0 {
			panic(fmt.Sprintf("x509 cert raw is empty"))
		}
	}
	return 1
}

func FuzzUnmarshalCertificatesFromPEM(data []byte) int {
	b, _ := pem.Decode(data)
	if b == nil {
		return 0
	}
	result, err := cryptoutils.UnmarshalCertificatesFromPEM(data)
	if err != nil {
		if result != nil {
			panic(fmt.Sprintf("result %v should be nil when there is an error %v", result, err))
		}
		return 0
	}
	for _, cert := range result {
		if len(cert.Raw) == 0 {
			panic(fmt.Sprintf("x509 cert raw is empty"))
		}
	}
	return 1
}

func FuzzUnmarshalPEMToPublicKey(data []byte) int {
	b, _ := pem.Decode(data)
	if b == nil {
		return 0
	}
	result, err := cryptoutils.UnmarshalPEMToPublicKey(data)
	if err != nil {
		if result != nil {
			panic(fmt.Sprintf("result %v should be nil when there is an error %v", result, err))
		}
		return 0
	}
	if result == nil {
		panic("result %v should not be nil ")
	}
	return 1
}
