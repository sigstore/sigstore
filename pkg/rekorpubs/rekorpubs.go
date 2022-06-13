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

package rekorpubs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/tuf"
)

// This is the rekor public key target name
var rekorTargetStr = `rekor.pub`

// RekorPubKey contains the ECDSA verification key and the current status
// of the key according to TUF metadata, whether it's active or expired.
type RekorPubKey struct {
	PubKey *ecdsa.PublicKey
	Status tuf.StatusKind
}

var (
	rekorOnce         = new(sync.Once)
	rekorPubKeys      map[string]RekorPubKey
	singletonRekorErr error
)

// GetLogID generates a SHA256 hash of a DER-encoded public key.
func GetLogID(pub crypto.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(pubBytes)
	return hex.EncodeToString(digest[:]), nil
}

// GetRekorPubs returns a map of rekor public keys keyed by rekor log ID. Each key contains
// the ecdsa public key of the log and the status of the log (e.g. Active, Inactive).
func GetRekorPubs() (map[string]RekorPubKey, error) {
	rekorOnce.Do(func() {
		rekorPubKeys = make(map[string]RekorPubKey)
		tufClient, err := tuf.NewFromEnv(context.Background())
		if err != nil {
			singletonRekorErr = fmt.Errorf("initializing tuf: %w", err)
			return
		}
		targets, err := tufClient.GetTargetsByMeta(tuf.Rekor, []string{rekorTargetStr})
		if err != nil {
			singletonRekorErr = fmt.Errorf("error getting targets: %w", err)
			return
		}
		for _, t := range targets {
			rekorPubKey, err := cryptoutils.UnmarshalPEMToECDSAKey(t.Target)
			if err != nil {
				singletonRekorErr = fmt.Errorf("pem to ecdsa: %w", err)
				return
			}
			keyID, err := GetLogID(rekorPubKey)
			if err != nil {
				singletonRekorErr = fmt.Errorf("error generating log ID: %w", err)
				return
			}
			rekorPubKeys[keyID] = RekorPubKey{PubKey: rekorPubKey, Status: t.Status}
		}
	})

	return rekorPubKeys, singletonRekorErr
}
