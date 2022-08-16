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

import "time"

// CacheKind is used to designate an on-disk or in-memory cache.
type CacheKind int

const (
	Disk CacheKind = iota
	Memory
)

// TUFOptions are the configurable TUF options used for the TUF configuration.
type TUFOptions struct {
	// CacheValidity is used to indicate how long to use unexpired cached metadata
	// before fetching an update from the remote repository.
	// Default: Three days.
	CacheValidity time.Duration

	// ForceCache is used to always used unexpired cached metadata before
	// fetching an update from the remote repository.
	// Default: False. This option is discouraged.
	ForceCache bool

	// This indicates whether the cache should be in the local filesystem or in-memory.
	// Default: Local.
	CacheType CacheKind

	// RootLocation is the location for the local TUF root.
	// Only applies when CacheType is Disk.
	// This directory will contain the metadata and targets cache for all
	// repositories in the map and the map.json configuration file.
	// Defaults: $HOME/.sigstore/root.
	RootLocation string
}

// RepositoryOptions specify options for initializing sigstore TUF with a particular
// repository. Specifies a root.json, a remote, and a name.
// TODO: Replace with a map.json repository mapping.
type RepositoryOptions struct {
	// The trusted root.json
	Root []byte

	// The location of the remote repository.
	Remote string

	// The name of the repository, used to populate the map.json. TODO: Make this
	// optional and use digest of the root.
	Name string
}
