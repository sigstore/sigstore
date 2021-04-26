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

package signfile

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"

	"github.com/go-openapi/swag"
	"github.com/pkg/errors"

	"github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/tlog"
)

type SignedPayload struct {
	Base64Signature string
	Payload         []byte
	Cert            *x509.Certificate
	Chain           []*x509.Certificate
}

func UploadToRekor(publicKey crypto.PublicKey, digest []byte, signedMsg []byte, rekorUrl string, certPEM []byte, payload []byte) (string, error) {
	rekorClient, err := app.GetRekorClient(rekorUrl)
	if err != nil {
		return "", err
	}

	wrappedKey, err := MarshalPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	re := tlog.RekorEntry(payload, signedMsg, certPEM)
	returnVal := models.Rekord{
		APIVersion: swag.String(re.APIVersion()),
		Spec:       re.RekordObj,
	}
	params := entries.NewCreateLogEntryParams()
	params.SetProposedEntry(&returnVal)
	resp, err := rekorClient.Entries.CreateLogEntry(params)

	if err != nil {
		// If the entry already exists, we get a specific error.
		// Here, we display the proof and succeed.
		if _, ok := err.(*entries.CreateLogEntryConflict); ok {
			cs := SignedPayload{
				Base64Signature: base64.StdEncoding.EncodeToString(signedMsg),
				Payload:         digest[:],
			}
			fmt.Println("Signature already exists. Displaying proof")

			return tlog.FindTlogEntry(rekorClient, cs.Base64Signature, cs.Payload, wrappedKey)
		}
		return "", err
	}
	// UUID is at the end of location
	for _, p := range resp.Payload {
		return strconv.FormatInt(*p.LogIndex, 10), nil
	}
	return "", errors.New("bad response from server")
}

func MarshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("empty key")
	}
	pubKey, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic("failed to marshall public key")
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKey,
	})
	return pubBytes, nil
}
