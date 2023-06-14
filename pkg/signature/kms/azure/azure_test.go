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

package azure

import "testing"

func TestParseReference(t *testing.T) {
	tests := []struct {
		in             string
		wantVaultURL   string
		wantVaultName  string
		wantKeyName    string
		wantKeyVersion string
		wantErr        bool
	}{
		{
			in:             "azurekms://honk-vault.vault.azure.net/honk-key",
			wantVaultURL:   "https://honk-vault.vault.azure.net/",
			wantVaultName:  "honk-vault",
			wantKeyName:    "honk-key",
			wantKeyVersion: "",
			wantErr:        false,
		},
		{
			in:             "azurekms://honk-vault.vault.azure.net/honk-key/123abc",
			wantVaultURL:   "https://honk-vault.vault.azure.net/",
			wantVaultName:  "honk-vault",
			wantKeyName:    "honk-key",
			wantKeyVersion: "123abc",
			wantErr:        false,
		},
		{
			in:      "foo://bar",
			wantErr: true,
		},
		{
			in:      "",
			wantErr: true,
		},
		{
			in:      "azurekms://wrong-test/test/1/3",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			gotVaultURL, gotVaultName, gotKeyName, gotKeyVersion, err := parseReference(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotVaultURL != tt.wantVaultURL {
				t.Errorf("parseReference() gotVaultURL = %v, want %v", gotVaultURL, tt.wantVaultURL)
			}
			if gotVaultName != tt.wantVaultName {
				t.Errorf("parseReference() gotVaultName = %v, want %v", gotVaultName, tt.wantVaultName)
			}
			if gotKeyName != tt.wantKeyName {
				t.Errorf("parseReference() gotKeyName = %v, want %v", gotKeyName, tt.wantKeyName)
			}
			if gotKeyVersion != tt.wantKeyVersion {
				t.Errorf("parseReference() gotKeyVersion = %v, want %v", gotKeyVersion, tt.wantKeyVersion)
			}
		})
	}
}
