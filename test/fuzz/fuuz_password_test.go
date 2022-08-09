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
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func FuzzGetPassword(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		original := cryptoutils.Read
		cryptoutils.Read = func() func() ([]byte, error) {
			return func() ([]byte, error) {
				return data, nil
			}
		}
		defer func() { cryptoutils.Read = original }()
		p, err := cryptoutils.GetPasswordFromStdIn(true)
		if err != nil {
			t.Errorf("error in getting the password %v", err)
		}
		// the password we got back is not what was entered
		if bytes.Compare(p, data) != 0 {
			t.Errorf("password %v does not match %v", p, data)
		}
		t.Skip("invalid data")
	})
}
