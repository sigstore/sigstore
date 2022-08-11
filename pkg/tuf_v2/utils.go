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

package tuf_v2

import (
	"encoding/json"
	"time"

	"github.com/theupdateframework/go-tuf/data"
)

/* This file implements TUF metadata format utilities */

// All TUF metadata implements signedMeta.
type signedMeta struct {
	Type    string    `json:"_type"`
	Expires time.Time `json:"expires"`
	Version int64     `json:"version"`
}

// getSignedMetadata converts a TUF metadata file in bytes to a signedMeta
// structure.
func getSignedMetadata(metadata []byte) (*signedMeta, error) {
	s := &data.Signed{}
	if err := json.Unmarshal(metadata, s); err != nil {
		return nil, err
	}
	sm := &signedMeta{}
	if err := json.Unmarshal(s.Signed, sm); err != nil {
		return nil, err
	}
	return sm, nil
}

func isMetadataExpired(metadata []byte) bool {
	sm, err := getSignedMetadata(metadata)
	if err != nil {
		return true
	}
	return time.Until(sm.Expires) <= 0
}
