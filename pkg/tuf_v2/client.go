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
	"errors"
	"fmt"
	"sync"

	"github.com/theupdateframework/go-tuf/client"
)

/*
Major TODO items:
  * Resolve CacheValidity issue: where do we get the cache time from?
  * Support multi-repository TUF client
  * Implement an InitializeWithDefaults that calls Initialize with
    default RepositoryOptions/mapping.
  * Implement a force update flag.
  * Create an in-memory mirror of the repository and target store to avoid
    file reads.
  * GetTarget implementation
*/

var (
	// singletonTUF holds a single instance of TUF that will get reused on
	// subsequent invocations of initializeTUF.
	singletonTUF     *TUF
	singletonTUFOnce = new(sync.Once)
	singletonTUFErr  error
)

// This is the Sigstore TUF client.
//
// TODO: Implement an in-memory metadata mirror and target storage.
type TUF struct {
	sync.Mutex

	// client is the base TUF client.
	// TODO: Replace when go-tuf implements a TAP-4 multi-repository client.
	// https://github.com/theupdateframework/go-tuf/issues/348
	client *client.Client

	// local is the TUF local repository for accessing local trusted metadata.
	local client.LocalStore

	// remote is the TUF remote repository for fetching remote metadata and
	// targets.
	remote client.RemoteStore

	// An implementation of the TAP-4 map.json. For now, we support a single
	// repository and is only used to track the location of the remote.
	// This is a configurable repository map.json defined according to TAP 4.
	// https://github.com/theupdateframework/taps/blob/master/tap4.md
	mapping RepositoryMap
}

// Initialize creates a new Sigstore TUF client using the supplied TUFOptions and
// RepositoryOptions.
//
// TODO(asraa): Right now we don't have multi-repository clients. When that happens,
// we will likely need to parse an existing map.json and augment it if Repository
// Options are provided.
func Initialize(opts *TUFOptions, repoOpts *RepositoryOptions) (*TUF, error) {
	singletonTUFOnce.Do(func() {
		t := &TUF{}

		if t.local, singletonTUFErr = localStoreFromOpts(opts, repoOpts); singletonTUFErr != nil {
			return
		}
		if t.remote, singletonTUFErr = remoteStoreFromOpts(repoOpts); singletonTUFErr != nil {
			return
		}
		t.client = client.NewClient(t.local, t.remote)

		root, singletonTUFErr := getTrustedRoot(t.local, repoOpts)
		if singletonTUFErr != nil {
			return
		}

		// Initialize TUF client with the trusted root.
		if err := t.client.InitLocal(root); err != nil {
			singletonTUFErr = fmt.Errorf("initializing client, local cache may be corrupt: %w", err)
			return
		}

		// Check if the local repository is valid: i.e. timestamp is unexpired and
		// the cache is valid.
		localValid, err := isLocalValid(t.local, opts)
		if err != nil {
			singletonTUFErr = err
			return
		}

		// TODO: Implement an explicit force update.
		if !localValid {
			// Update with the TUF client.
			if _, err := t.client.Update(); err != nil {
				singletonTUFErr = fmt.Errorf("updating client: %w", err)
				return
			}
		}

		singletonTUF = t
	})
	return singletonTUF, singletonTUFErr
}

// GetTargetsForUsage gets targets for a particular usage kind, searching in
// filepaths begining with $USAGE/**.
// Returns a map of target files.
func (t *TUF) GetTargetsForUsage(usage UsageKind) (map[string]interface{}, error) {
	return nil, errors.New("unimplemented")
}

// Returns a boolean indicating whether the local repository is valid according
// to the supplied TUF options.
func isLocalValid(local client.LocalStore, opts *TUFOptions) (bool, error) {
	trustedMeta, err := local.GetMeta()
	if err != nil {
		return false, fmt.Errorf("getting trusted meta: %w", err)
	}

	trustedTimestamp, ok := trustedMeta["timestamp.json"]
	if !ok {
		// No timestamp -- that's OK, get an Update.
		return false, nil
	}

	// If the local timestamp is expired, we definitely need an update.
	if isMetadataExpired(trustedTimestamp) {
		return false, nil
	}

	// Otherwise, check if the cache is valid according to the cache options.
	// TODO: IMPLEMENT CacheValidity!! This will allow for local cache usage for
	// a certain duration. How to access file creation time?
	if opts.ForceCache {
		// Return early. Timestamp is not expired and we have a valid cache!
		return true, nil
	}

	// Cache isn't valid, we require an update.
	return false, nil
}

func getTrustedRoot(local client.LocalStore, repoOpts *RepositoryOptions) ([]byte, error) {
	// Check if the local already specifies a root.
	localMetadata, err := local.GetMeta()
	if err != nil {
		return nil, fmt.Errorf("error accessing local metadata: %w", err)
	}
	if trustedRoot, ok := localMetadata["root.json"]; ok {
		return trustedRoot, nil
	}

	// If not, use the one provided in repoOpts.
	return repoOpts.Root, nil
}
