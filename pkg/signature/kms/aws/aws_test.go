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

package aws

import "testing"

func TestParseReference(t *testing.T) {
	tests := []struct {
		in           string
		wantEndpoint string
		wantKeyID    string
		wantAlias    string
		wantErr      bool
	}{
		{
			in:           "awskms:///1234abcd-12ab-34cd-56ef-1234567890ab",
			wantEndpoint: "",
			wantKeyID:    "1234abcd-12ab-34cd-56ef-1234567890ab",
			wantAlias:    "",
			wantErr:      false,
		},
		{
			// multi-region key
			in:           "awskms:///mrk-1234abcd12ab34cd56ef1234567890ab",
			wantEndpoint: "",
			wantKeyID:    "mrk-1234abcd12ab34cd56ef1234567890ab",
			wantAlias:    "",
			wantErr:      false,
		},
		{
			in:           "awskms:///1234ABCD-12AB-34CD-56EF-1234567890AB",
			wantEndpoint: "",
			wantKeyID:    "1234ABCD-12AB-34CD-56EF-1234567890AB",
			wantAlias:    "",
			wantErr:      false,
		},
		{
			in:           "awskms://localhost:4566/1234abcd-12ab-34cd-56ef-1234567890ab",
			wantEndpoint: "localhost:4566",
			wantKeyID:    "1234abcd-12ab-34cd-56ef-1234567890ab",
			wantAlias:    "",
			wantErr:      false,
		},
		{
			in:           "awskms:///arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			wantEndpoint: "",
			wantKeyID:    "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			wantAlias:    "",
			wantErr:      false,
		},
		{
			in:           "awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			wantEndpoint: "localhost:4566",
			wantKeyID:    "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			wantAlias:    "",
			wantErr:      false,
		},
		{
			in:           "awskms:///alias/ExampleAlias",
			wantEndpoint: "",
			wantKeyID:    "alias/ExampleAlias",
			wantAlias:    "alias/ExampleAlias",
			wantErr:      false,
		},
		{
			in:           "awskms://localhost:4566/alias/ExampleAlias",
			wantEndpoint: "localhost:4566",
			wantKeyID:    "alias/ExampleAlias",
			wantAlias:    "alias/ExampleAlias",
			wantErr:      false,
		},
		{
			in:           "awskms:///arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias",
			wantEndpoint: "",
			wantKeyID:    "arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias",
			wantAlias:    "alias/ExampleAlias",
			wantErr:      false,
		},
		{
			in:           "awskms:///arn:aws-us-gov:kms:us-gov-west-1:111122223333:alias/ExampleAlias",
			wantEndpoint: "",
			wantKeyID:    "arn:aws-us-gov:kms:us-gov-west-1:111122223333:alias/ExampleAlias",
			wantAlias:    "alias/ExampleAlias",
			wantErr:      false,
		},
		{
			in:           "awskms:///arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			wantEndpoint: "",
			wantKeyID:    "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			wantAlias:    "",
			wantErr:      false,
		},
		{
			in:           "awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias",
			wantEndpoint: "localhost:4566",
			wantKeyID:    "arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias",
			wantAlias:    "alias/ExampleAlias",
			wantErr:      false,
		},
		{
			// missing alias/ prefix
			in:           "awskms:///missingalias",
			wantEndpoint: "",
			wantKeyID:    "",
			wantAlias:    "",
			wantErr:      true,
		},
		{
			// invalid UUID
			in:           "awskms:///1234abcd-12ab-YYYY-56ef-1234567890ab",
			wantEndpoint: "",
			wantKeyID:    "",
			wantAlias:    "",
			wantErr:      true,
		},
		{
			// Currently, references without endpoints must use 3
			// slashes. It would be nice to support this format,
			// but that would be harder to parse.
			in:           "awskms://1234abcd-12ab-34cd-56ef-1234567890ab",
			wantEndpoint: "",
			wantKeyID:    "",
			wantAlias:    "",
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			gotEndpoint, gotKeyID, gotAlias, err := ParseReference(tt.in)
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
			if gotAlias != tt.wantAlias {
				t.Errorf("ParseReference() gotAlias = %v, want %v", gotAlias, tt.wantAlias)
			}
		})
	}
}
