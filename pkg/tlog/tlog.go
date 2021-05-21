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

package tlog

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/pkg/errors"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
)

func FindTlogEntry(rekorClient *client.Rekor, b64Sig string, payload, pubKey []byte) (string, error) {
	searchParams := entries.NewSearchLogQueryParams()
	searchLogQuery := models.SearchLogQuery{}
	signature, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return "", errors.Wrap(err, "decoding base64 signature")
	}
	re := RekorEntry(payload, signature, pubKey)
	entry := &models.Rekord{
		APIVersion: swag.String(re.APIVersion()),
		Spec:       re.RekordObj,
	}

	searchLogQuery.SetEntries([]models.ProposedEntry{entry})

	searchParams.SetEntry(&searchLogQuery)
	resp, err := rekorClient.Entries.SearchLogQuery(searchParams)
	if err != nil {
		return "", errors.Wrap(err, "searching log query")
	}
	if len(resp.Payload) == 0 {
		return "", errors.New("signature not found in transparency log")
	} else if len(resp.Payload) > 1 {
		return "", errors.New("multiple entries returned; this should not happen")
	}
	logEntry := resp.Payload[0]
	if len(logEntry) != 1 {
		return "", errors.New("UUID value can not be extracted")
	}

	params := entries.NewGetLogEntryByUUIDParams()
	for k := range logEntry {
		params.EntryUUID = k
	}
	lep, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return "", err
	}

	if len(lep.Payload) != 1 {
		return "", errors.New("UUID value can not be extracted")
	}
	e := lep.Payload[params.EntryUUID]

	hashes := [][]byte{}
	for _, h := range e.Verification.InclusionProof.Hashes {
		hb, _ := hex.DecodeString(h)
		hashes = append(hashes, hb)
	}

	rootHash, _ := hex.DecodeString(*e.Verification.InclusionProof.RootHash)
	leafHash, _ := hex.DecodeString(params.EntryUUID)

	v := logverifier.New(hasher.DefaultHasher)
	if err := v.VerifyInclusionProof(*e.Verification.InclusionProof.LogIndex, *e.Verification.InclusionProof.TreeSize, hashes, rootHash, leafHash); err != nil {
		return "", errors.Wrap(err, "verifying inclusion proof")
	}
	return params.EntryUUID, nil
}

func RekorEntry(payload, signature, pubKey []byte) rekord_v001.V001Entry {
	return rekord_v001.V001Entry{
		RekordObj: models.RekordV001Schema{
			Data: &models.RekordV001SchemaData{
				Content: strfmt.Base64(payload),
			},
			Signature: &models.RekordV001SchemaSignature{
				Content: strfmt.Base64(signature),
				Format:  models.RekordV001SchemaSignatureFormatX509,
				PublicKey: &models.RekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(pubKey),
				},
			},
		},
	}
}
