//
// Copyright 2023 The Sigstore Authors.
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

package yckms

import (
	"testing"
)

func TestParseReference(t *testing.T) {
	tests := []struct {
		in           string
		wantEndpoint string
		wantKeyID    string
		wantFolderId string
		wantKeyName  string
		wantErr      bool
	}{
		{
			in:           "yckms:///abc1234abcd12ab34cd",
			wantEndpoint: "",
			wantKeyID:    "abc1234abcd12ab34cd",
			wantFolderId: "",
			wantKeyName:  "",
			wantErr:      false,
		},
		{
			in:           "yckms:///somekeyid",
			wantEndpoint: "",
			wantKeyID:    "somekeyid",
			wantFolderId: "",
			wantKeyName:  "",
			wantErr:      false,
		},
		{
			in:           "yckms:///ABC1234ABCD12AB34CD",
			wantEndpoint: "",
			wantKeyID:    "ABC1234ABCD12AB34CD",
			wantFolderId: "",
			wantKeyName:  "",
			wantErr:      false,
		},
		{
			in:           "yckms://localhost:443/abc1234abcd12ab34cd",
			wantEndpoint: "localhost:443",
			wantKeyID:    "abc1234abcd12ab34cd",
			wantFolderId: "",
			wantKeyName:  "",
			wantErr:      false,
		},
		{
			in:           "yckms:///folder/abc123bcd12/keyname/test-key",
			wantEndpoint: "",
			wantKeyID:    "",
			wantFolderId: "abc123bcd12",
			wantKeyName:  "test-key",
			wantErr:      false,
		},
		{
			in:           "yckms://localhost:443/folder/abc123bcd12/keyname/test-key",
			wantEndpoint: "localhost:443",
			wantKeyID:    "",
			wantFolderId: "abc123bcd12",
			wantKeyName:  "test-key",
			wantErr:      false,
		},
		{
			in:           "yckms:///keyname/test-keyname",
			wantEndpoint: "",
			wantKeyID:    "",
			wantFolderId: "",
			wantKeyName:  "",
			wantErr:      true,
		},
		{
			in:           "yckms:///folder/abc123bcd12",
			wantEndpoint: "",
			wantKeyID:    "",
			wantFolderId: "",
			wantKeyName:  "",
			wantErr:      true,
		},
		{
			in:           "yckms:///folder/abc123bcd12/keyname",
			wantEndpoint: "",
			wantKeyID:    "",
			wantFolderId: "",
			wantKeyName:  "",
			wantErr:      true,
		},
		{
			// Currently, references without endpoints must use 3
			// slashes. It would be nice to support this format,
			// but that would be harder to parse.
			in:           "yckms://abc1234abcd12ab34cd",
			wantEndpoint: "",
			wantKeyID:    "",
			wantFolderId: "",
			wantKeyName:  "",
			wantErr:      true,
		},
		{
			// Currently, references without endpoints must use 3
			// slashes. It would be nice to support this format,
			// but that would be harder to parse.
			in:           "yckms://folder/abc123bcd12/keyname/test-key",
			wantEndpoint: "",
			wantKeyID:    "",
			wantFolderId: "",
			wantKeyName:  "",
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			gotEndpoint, gotKeyID, gotFolderID, gotKeyName, err := ParseReference(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotEndpoint != tt.wantEndpoint {
				t.Errorf("ParseReference() gotEndpoint = %v, want %v", gotEndpoint, tt.wantEndpoint)
			}
			if gotKeyID != tt.wantKeyID {
				t.Errorf("ParseReference() gotKeyID = %v, want %v", gotKeyID, tt.wantKeyID)
			}
			if gotFolderID != tt.wantFolderId {
				t.Errorf("ParseReference() gotFolderID = %v, want %v", gotFolderID, tt.wantFolderId)
			}
			if gotKeyName != tt.wantKeyName {
				t.Errorf("ParseReference() gotKeyName = %v, want %v", gotKeyName, tt.wantKeyName)
			}
		})
	}
}
