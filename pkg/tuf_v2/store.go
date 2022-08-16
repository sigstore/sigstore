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
	"net/url"
	"path/filepath"

	"github.com/theupdateframework/go-tuf/client"
	tuf_leveldbstore "github.com/theupdateframework/go-tuf/client/leveldbstore"
)

// localStoreFromOpts creates a local store depending on the TUF configuration
// and uses the RepositoryOptions to name the metadata directory.
func localStoreFromOpts(opts *TUFOptions, repoOpts *RepositoryOptions) (client.LocalStore, error) {
	switch opts.CacheType {
	case Disk:
		if repoOpts != nil && repoOpts.Name != "" {
			return nil, errors.New("must specify a name in repository options")
		}
		// TODO: Replace with filesystem representation.
		tufDB := filepath.FromSlash(filepath.Join(opts.RootLocation, repoOpts.Name, "tuf.db"))
		return tuf_leveldbstore.FileLocalStore(tufDB)
	case Memory:
		return client.MemoryLocalStore(), nil
	}
	return nil, errors.New("unknown cache type")
}

// remoteStoreFromOpts creates the remote store using the RepositoryOptions.
func remoteStoreFromOpts(repoOpts *RepositoryOptions) (client.RemoteStore, error) {
	if _, err := url.ParseRequestURI(repoOpts.Remote); err != nil {
		return nil, fmt.Errorf("failed to parse remote URL %s: %w", repoOpts.Remote, err)
	}
	return client.HTTPRemoteStore(repoOpts.Remote, nil, nil)
}
