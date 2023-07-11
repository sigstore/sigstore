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

package ehsm

import "testing"

func TestParseReference(t *testing.T) {
	tests := []struct {
		in      string
		wantKey string
		wantErr bool
	}{
		{
			in:      "ehsm://cosign",
			wantKey: "cosign",
			wantErr: false,
		},
		{
			in:      "foo://bar",
			wantErr: true,
		},
		{
			in:      "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			gotKey, err := parseReference(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotKey != tt.wantKey {
				t.Errorf("parseReference() gotKey = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}
