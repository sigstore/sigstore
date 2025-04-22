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

package tuf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/verify"
)

// These are the expected targets from the Sigstore root.
// This may not be the total complete list to ensure that targets
// can be added during new ceremonies.
var targets = []string{
	"artifact.pub",
	"fulcio_v1.crt.pem",
	"ctfe.pub",
	"rekor.pub",
	"ctfe_2022.pub",
	"fulcio.crt.pem",
	"fulcio_intermediate_v1.crt.pem",
	"trusted_root.json",
}

func TestNewFromEnv(t *testing.T) {
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)
	ctx := context.Background()

	// Make sure nothing is expired
	tuf, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}

	checkTargetsAndMeta(t, tuf, targets)
	resetForTests()

	// Now try with expired targets
	forceExpiration(t, true)
	tuf, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkTargetsAndMeta(t, tuf, targets)
	resetForTests()

	if err := Initialize(ctx, DefaultRemoteRoot, nil); err != nil {
		t.Error()
	}
	if l := dirLen(t, td); l == 0 {
		t.Errorf("expected filesystem writes, got %d entries", l)
	}

	// And go from there!
	tuf, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkTargetsAndMeta(t, tuf, targets)
	resetForTests()
}

func TestLegacyURLToCDN(t *testing.T) {
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)
	remoteInfo := &remoteCache{Mirror: defaultRemoteRootNoCDN}
	b, err := json.Marshal(remoteInfo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachedRemote(td), b, 0o600); err != nil {
		t.Fatalf("storing remote: %v", err)
	}

	// First initialization, populate the cache.
	tuf, err := NewFromEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tuf.Mirror() != DefaultRemoteRoot {
		t.Fatal("legacy prod GCS HTTP endpoint was not mapped to CDN")
	}
}

func TestAltLegacyURLToCDN(t *testing.T) {
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)
	remoteInfo := &remoteCache{Mirror: defaultRemoteRootNoCDNAlt}
	b, err := json.Marshal(remoteInfo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachedRemote(td), b, 0o600); err != nil {
		t.Fatalf("storing remote: %v", err)
	}

	// First initialization, populate the cache.
	tuf, err := NewFromEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tuf.Mirror() != DefaultRemoteRoot {
		t.Fatal("legacy prod GCS HTTP endpoint was not mapped to CDN")
	}
}

func TestCDNRewriteforMirror(t *testing.T) {
	tuf := &TUF{
		mirror: defaultRemoteGCSBucket,
	}
	if tuf.Mirror() != DefaultRemoteRoot {
		t.Fatal("reference to default remote GCS bucket was not redirected to CDN")
	}

	tuf.mirror = defaultRemoteRootNoCDN
	if tuf.Mirror() != DefaultRemoteRoot {
		t.Fatal("reference to default remote GCS HTTP endpoint was not redirected to CDN")
	}

	tuf.mirror = defaultRemoteRootNoCDNAlt
	if tuf.Mirror() != DefaultRemoteRoot {
		t.Fatal("reference to alternate remote GCS HTTP endpoint was not redirected to CDN")
	}
}

func TestLegacyBucketToCDN(t *testing.T) {
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)
	remoteInfo := &remoteCache{Mirror: defaultRemoteGCSBucket}
	b, err := json.Marshal(remoteInfo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachedRemote(td), b, 0o600); err != nil {
		t.Fatalf("storing remote: %v", err)
	}

	// First initialization, populate the cache.
	tuf, err := NewFromEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tuf.Mirror() != DefaultRemoteRoot {
		t.Fatal("legacy prod bucket was not mapped to CDN")
	}
}

func TestNoCache(t *testing.T) {
	ctx := context.Background()
	// Once more with NO_CACHE
	t.Setenv("SIGSTORE_NO_CACHE", "true")
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)

	// First initialization, populate the cache.
	tuf, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkTargetsAndMeta(t, tuf, targets)
	resetForTests()

	// Force expiration so we have some content to download
	forceExpiration(t, true)

	tuf, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkTargetsAndMeta(t, tuf, targets)
	resetForTests()

	// No filesystem writes when using SIGSTORE_NO_CACHE.
	if l := dirLen(t, td); l != 0 {
		t.Errorf("expected no filesystem writes, got %d entries", l)
	}
	resetForTests()
}

func TestCache(t *testing.T) {
	ctx := context.Background()
	// Once more with cache.
	t.Setenv("SIGSTORE_NO_CACHE", "false")
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)

	// Make sure nothing is in that directory to start with
	if l := dirLen(t, td); l != 0 {
		t.Errorf("expected no filesystem writes, got %d entries", l)
	}

	// First initialization, populate the cache. Expect disk writes.
	tuf, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkTargetsAndMeta(t, tuf, targets)
	resetForTests()
	cachedDirLen := dirLen(t, td)
	if cachedDirLen == 0 {
		t.Errorf("expected filesystem writes, got %d entries", cachedDirLen)
	}

	// Nothing should get downloaded if everything is up to date.
	forceExpiration(t, false)
	_, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resetForTests()

	if l := dirLen(t, td); cachedDirLen != l {
		t.Errorf("expected no filesystem writes, got %d entries", l-cachedDirLen)
	}

	// Forcing expiration, but expect no disk writes because all targets up to date.
	forceExpiration(t, true)
	tuf, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if l := dirLen(t, td); l != cachedDirLen {
		t.Errorf("expected filesystem writes, got %d entries", l)
	}
	checkTargetsAndMeta(t, tuf, targets)
	resetForTests()
}

func TestCustomRoot(t *testing.T) {
	ctx := context.Background()
	// Create a remote repository.
	td := t.TempDir()
	remote, r := newTufRepo(t, td, "foo")

	// Serve remote repository.
	s := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(td, "repository"))))
	defer s.Close()

	// Initialize with custom root.
	tufRoot := t.TempDir()
	t.Setenv("TUF_ROOT", tufRoot)
	meta, err := remote.GetMeta()
	if err != nil {
		t.Error(err)
	}
	rootBytes, ok := meta["root.json"]
	if !ok {
		t.Error(err)
	}
	if err := Initialize(ctx, s.URL, rootBytes); err != nil {
		t.Error(err)
	}
	if l := dirLen(t, tufRoot); l == 0 {
		t.Errorf("expected filesystem writes, got %d entries", l)
	}

	// Successfully get target.
	tufObj, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := tufObj.GetTarget("foo.txt"); err != nil || !bytes.Equal(b, []byte("foo")) {
		t.Fatal(err)
	}
	resetForTests()

	// Force expiration on the first timestamp and internal go-tuf verification.
	forceExpirationVersion(t, 1)
	oldIsExpired := verify.IsExpired
	verify.IsExpired = func(time time.Time) bool {
		return true
	}

	// This should cause an error that remote metadata is expired.
	if _, err = NewFromEnv(ctx); err == nil {
		t.Errorf("expected expired timestamp from the remote")
	}

	// Let internal TUF verification succeed normally now.
	verify.IsExpired = oldIsExpired

	// Update remote targets, issue a timestamp v2.
	updateTufRepo(t, td, r, "foo1")

	// Use newTuf and successfully get updated metadata using the cached remote location.
	resetForTests()
	tufObj, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := tufObj.GetTarget("foo.txt"); err != nil || !bytes.Equal(b, []byte("foo1")) {
		t.Fatal(err)
	}
	resetForTests()
}

func TestCustomRootFileRemoteStore(t *testing.T) {
	ctx := context.Background()
	// Create a remote repository.
	td := t.TempDir()
	remote, r := newTufRepo(t, td, "foo")

	// Initialize with custom root.
	tufRoot := t.TempDir()
	t.Setenv("TUF_ROOT", tufRoot)
	meta, err := remote.GetMeta()
	if err != nil {
		t.Error(err)
	}
	rootBytes, ok := meta["root.json"]
	if !ok {
		t.Error(err)
	}
	// Tack on repository to the end of the td above since that's where
	// newTufRepo creates the repository.
	fileURI := fmt.Sprintf("file://%s", filepath.Join(td, "repository"))
	if err := Initialize(ctx, fileURI, rootBytes); err != nil {
		t.Error(err)
	}
	if l := dirLen(t, tufRoot); l == 0 {
		t.Errorf("expected filesystem writes, got %d entries", l)
	}

	// Successfully get target.
	tufObj, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := tufObj.GetTarget("foo.txt"); err != nil || !bytes.Equal(b, []byte("foo")) {
		t.Fatal(err)
	}
	resetForTests()

	// Force expiration on the first timestamp and internal go-tuf verification.
	forceExpirationVersion(t, 1)
	oldIsExpired := verify.IsExpired
	verify.IsExpired = func(time time.Time) bool {
		return true
	}

	// This should cause an error that remote metadata is expired.
	if _, err = NewFromEnv(ctx); err == nil {
		t.Errorf("expected expired timestamp from the remote")
	}

	// Let internal TUF verification succeed normally now.
	verify.IsExpired = oldIsExpired

	// Update remote targets, issue a timestamp v2.
	updateTufRepo(t, td, r, "foo1")

	// Use newTuf and successfully get updated metadata using the cached remote location.
	resetForTests()
	tufObj, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := tufObj.GetTarget("foo.txt"); err != nil || !bytes.Equal(b, []byte("foo1")) {
		t.Fatal(err)
	}
	resetForTests()
}

func TestGetTargetsByMeta(t *testing.T) {
	ctx := context.Background()
	// Create a remote repository.
	td := t.TempDir()
	remote, _ := newTufCustomRepo(t, td, "foo")

	// Serve remote repository.
	s := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(td, "repository"))))
	defer s.Close()

	// Initialize with custom root.
	tufRoot := t.TempDir()
	t.Setenv("TUF_ROOT", tufRoot)
	meta, err := remote.GetMeta()
	if err != nil {
		t.Error(err)
	}
	rootBytes, ok := meta["root.json"]
	if !ok {
		t.Error(err)
	}
	if err := Initialize(ctx, s.URL, rootBytes); err != nil {
		t.Error(err)
	}
	if l := dirLen(t, tufRoot); l == 0 {
		t.Errorf("expected filesystem writes, got %d entries", l)
	}

	tufObj, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer resetForTests()
	// Fetch a target with no custom metadata.
	targets, err := tufObj.GetTargetsByMeta(UnknownUsage, []string{"fooNoCustom.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected one target without custom metadata, got %d targets", len(targets))
	}
	if !bytes.Equal(targets[0].Target, []byte("foo")) {
		t.Fatalf("target metadata mismatched, expected: %s, got: %s", "foo", string(targets[0].Target))
	}
	if targets[0].Status != Active {
		t.Fatalf("target without custom metadata not active, got: %v", targets[0].Status)
	}
	if targets[0].Name != "fooNoCustom.txt" {
		t.Fatalf("target has wrong name, expected: %s, got: %s", "fooNoCustom.txt", targets[0].Name)
	}
	// Fetch multiple targets with no custom metadata.
	targets, err = tufObj.GetTargetsByMeta(UnknownUsage, []string{"fooNoCustom.txt", "fooNoCustomOther.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected two targets without custom metadata, got %d targets", len(targets))
	}
	if targets[0].Status != Active || targets[1].Status != Active {
		t.Fatalf("target without custom metadata not active, got: %v and %v", targets[0].Status, targets[1].Status)
	}
	// Specify multiple fallbacks with no custom metadata.
	targets, err = tufObj.GetTargetsByMeta(UnknownUsage, []string{"fooNoCustom.txt", "fooNoCustomOtherMissingTarget.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected one targets without custom metadata, got %d targets", len(targets))
	}
	if targets[0].Status != Active {
		t.Fatalf("target without custom metadata not active, got: %v and %v", targets[0].Status, targets[1].Status)
	}
	// Fetch targets with custom metadata.
	targets, err = tufObj.GetTargetsByMeta(Fulcio, []string{"fooNoCustom.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected two targets without custom metadata, got %d targets", len(targets))
	}
	targetBytes := []string{string(targets[0].Target), string(targets[1].Target)}
	expectedTB := []string{"foo", "foo"}
	if !reflect.DeepEqual(targetBytes, expectedTB) {
		t.Fatalf("target metadata mismatched, expected: %v, got: %v", expectedTB, targetBytes)
	}
	targetNames := []string{targets[0].Name, targets[1].Name}
	sort.Strings(targetNames)
	expectedTN := []string{"fooActive.txt", "fooExpired.txt"}
	if !reflect.DeepEqual(targetNames, expectedTN) {
		t.Fatalf("target names mismatched, expected: %v, got: %v", expectedTN, targetNames)
	}
	targetStatuses := []StatusKind{targets[0].Status, targets[1].Status}
	sort.Slice(targetStatuses, func(i, j int) bool {
		return targetStatuses[i] < targetStatuses[j]
	})
	expectedTS := []StatusKind{Active, Expired}
	if !reflect.DeepEqual(targetStatuses, expectedTS) {
		t.Fatalf("unexpected target status with custom metadata, expected %v, got: %v", expectedTS, targetStatuses)
	}
	// Error when fetching target that does not exist.
	_, err = tufObj.GetTargetsByMeta(UsageKind(UnknownStatus), []string{"unknown.txt"})
	expectedErr := "file not found: unknown.txt"
	if !strings.Contains(err.Error(), "not found: unknown.txt") {
		t.Fatalf("unexpected error fetching missing metadata, expected: %s, got: %s", expectedErr, err.Error())
	}
}

func makeMapFS(repo string) (fs fstest.MapFS) {
	fs = make(fstest.MapFS)
	_ = filepath.Walk(repo,
		func(fpath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(repo, fpath)
			if info.IsDir() {
				fs[path.Join("repository", rel)] = &fstest.MapFile{Mode: os.ModeDir}
			} else {
				b, _ := os.ReadFile(fpath)
				fs[path.Join("repository", rel)] = &fstest.MapFile{Data: b}
			}
			return nil
		})
	return
}

// Regression test for failure to fetch a target that does not exist in the embedded
// repository on an update. The new target exists on the remote before the TUF object
// is initialized.
func TestUpdatedTargetNamesEmbedded(t *testing.T) {
	td := t.TempDir()
	// Set the TUF_ROOT so we don't interact with other tests and local TUF roots.
	t.Setenv("TUF_ROOT", td)

	origEmbedded := getEmbedded
	origDefaultRemote := getRemoteRoot

	// Create an "expired" embedded repository that does not contain newTarget.
	ctx := context.Background()
	store, r := newTufCustomRepo(t, td, "foo")
	repository := filepath.FromSlash(filepath.Join(td, "repository"))
	mapfs := makeMapFS(repository)
	getEmbedded = func() fs.FS { return mapfs }

	oldIsExpired := isExpiredTimestamp
	isExpiredTimestamp = func(metadata []byte) bool {
		m, _ := store.GetMeta()
		timestampExpires, _ := getExpiration(m["timestamp.json"])
		metadataExpires, _ := getExpiration(metadata)
		return metadataExpires.Sub(*timestampExpires) <= 0
	}
	defer func() {
		getEmbedded = origEmbedded
		getRemoteRoot = origDefaultRemote
		isExpiredTimestamp = oldIsExpired
	}()

	// Assert that the embedded repository does not contain the newTarget.
	newTarget := "fooNew.txt"
	rd, ok := getEmbedded().(fs.ReadFileFS)
	if !ok {
		t.Fatal("fs.ReadFileFS unimplemented for embedded repo")
	}
	if _, err := rd.ReadFile(path.Join("repository", "targets", newTarget)); err == nil {
		t.Fatal("embedded repository should not contain new target")
	}

	// Serve an updated remote repository with the newTarget.
	addNewCustomTarget(t, td, r, map[string]string{newTarget: "newdata"})
	s := httptest.NewServer(http.FileServer(http.Dir(repository)))
	defer s.Close()
	getRemoteRoot = func() string { return s.URL }

	// Initialize.
	tufObj, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer resetForTests()

	// Try to retrieve the newly added target.
	targets, err := tufObj.GetTargetsByMeta(Fulcio, []string{"fooNoCustom.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 {
		t.Fatalf("expected three target without custom metadata, got %d targets", len(targets))
	}
	targetBytes := []string{string(targets[0].Target), string(targets[1].Target), string(targets[2].Target)}
	expectedTB := []string{"foo", "foo", "newdata"}
	if !cmp.Equal(targetBytes, expectedTB,
		cmpopts.SortSlices(func(a, b string) bool { return a < b })) {
		t.Fatalf("target data mismatched, expected: %v, got: %v", expectedTB, targetBytes)
	}
}

func checkTargetsAndMeta(t *testing.T, tuf *TUF, expected []string) {
	// Check the targets
	t.Helper()
	for _, target := range expected {
		if _, err := tuf.GetTarget(target); err != nil {
			t.Fatal(err)
		}
	}

	// An invalid target
	if _, err := tuf.GetTarget("invalid"); err == nil {
		t.Error("expected error reading target, got nil")
	}

	// Check root status.
	_, err := tuf.getRootStatus()
	if err != nil {
		t.Fatal(err)
	}
}

func dirLen(t *testing.T, td string) int {
	t.Helper()
	de, err := os.ReadDir(td)
	if err != nil {
		t.Fatal(err)
	}
	return len(de)
}

func forceExpiration(t *testing.T, expire bool) {
	oldIsExpiredTimestamp := isExpiredTimestamp
	isExpiredTimestamp = func(_ []byte) bool {
		return expire
	}
	t.Cleanup(func() {
		isExpiredTimestamp = oldIsExpiredTimestamp
	})
}

func forceExpirationVersion(t *testing.T, version int64) {
	oldIsExpiredTimestamp := isExpiredTimestamp
	isExpiredTimestamp = func(metadata []byte) bool {
		s := &data.Signed{}
		if err := json.Unmarshal(metadata, s); err != nil {
			return true
		}
		sm := &data.Timestamp{}
		if err := json.Unmarshal(s.Signed, sm); err != nil {
			return true
		}
		return sm.Version <= version
	}
	t.Cleanup(func() {
		isExpiredTimestamp = oldIsExpiredTimestamp
	})
}

// newTufCustomRepo initializes a TUF repository with root, targets, snapshot, and timestamp roles
// 4 targets are created to exercise various code paths, including two targets with no custom metadata,
// one target with custom metadata marked as active, and another with custom metadata marked as expired.
func newTufCustomRepo(t *testing.T, td, targetData string) (tuf.LocalStore, *tuf.Repo) {
	scmActive, err := json.Marshal(&sigstoreCustomMetadata{Sigstore: customMetadata{Usage: Fulcio, Status: Active}})
	if err != nil {
		t.Error(err)
	}
	scmExpired, err := json.Marshal(&sigstoreCustomMetadata{Sigstore: customMetadata{Usage: Fulcio, Status: Expired}})
	if err != nil {
		t.Error(err)
	}

	remote := tuf.FileSystemStore(td, nil)
	r, err := tuf.NewRepo(remote)
	if err != nil {
		t.Error(err)
	}
	if err := r.Init(false); err != nil {
		t.Error(err)
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if _, err := r.GenKey(role); err != nil {
			t.Error(err)
		}
	}
	for name, scm := range map[string]json.RawMessage{
		"fooNoCustom.txt": nil, "fooNoCustomOther.txt": nil,
		"fooActive.txt": scmActive, "fooExpired.txt": scmExpired,
	} {
		targetPath := filepath.FromSlash(filepath.Join(td, "staged", "targets", name))
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			t.Error(err)
		}
		if err := os.WriteFile(targetPath, []byte(targetData), 0o600); err != nil {
			t.Error(err)
		}
		if err := r.AddTarget(name, scm); err != nil {
			t.Error(err)
		}
	}
	if err := r.Snapshot(); err != nil {
		t.Error(err)
	}
	if err := r.Timestamp(); err != nil {
		t.Error(err)
	}
	if err := r.Commit(); err != nil {
		t.Error(err)
	}
	return remote, r
}

func addNewCustomTarget(t *testing.T, td string, r *tuf.Repo, targetData map[string]string) {
	scmActive, err := json.Marshal(&sigstoreCustomMetadata{Sigstore: customMetadata{Usage: Fulcio, Status: Active}})
	if err != nil {
		t.Error(err)
	}

	for name, data := range targetData {
		targetPath := filepath.FromSlash(filepath.Join(td, "staged", "targets", name))
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			t.Error(err)
		}
		if err := os.WriteFile(targetPath, []byte(data), 0o600); err != nil {
			t.Error(err)
		}
		if err := r.AddTarget(name, scmActive); err != nil {
			t.Error(err)
		}
	}

	if err := r.Snapshot(); err != nil {
		t.Error(err)
	}
	if err := r.Timestamp(); err != nil {
		t.Error(err)
	}
	if err := r.Commit(); err != nil {
		t.Error(err)
	}
}

func newTufRepo(t *testing.T, td, targetData string) (tuf.LocalStore, *tuf.Repo) {
	remote := tuf.FileSystemStore(td, nil)
	r, err := tuf.NewRepo(remote)
	if err != nil {
		t.Error(err)
	}
	if err := r.Init(false); err != nil {
		t.Error(err)
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if _, err := r.GenKey(role); err != nil {
			t.Error(err)
		}
	}
	targetPath := filepath.FromSlash(filepath.Join(td, "staged", "targets", "foo.txt"))
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		t.Error(err)
	}
	if err := os.WriteFile(targetPath, []byte(targetData), 0o600); err != nil {
		t.Error(err)
	}
	if err := r.AddTarget("foo.txt", nil); err != nil {
		t.Error(err)
	}
	if err := r.Snapshot(); err != nil {
		t.Error(err)
	}
	if err := r.Timestamp(); err != nil {
		t.Error(err)
	}
	if err := r.Commit(); err != nil {
		t.Error(err)
	}
	return remote, r
}

func updateTufRepo(t *testing.T, td string, r *tuf.Repo, targetData string) {
	targetPath := filepath.FromSlash(filepath.Join(td, "staged", "targets", "foo.txt"))
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		t.Error(err)
	}
	if err := os.WriteFile(targetPath, []byte(targetData), 0o600); err != nil {
		t.Error(err)
	}
	if err := r.AddTarget("foo.txt", nil); err != nil {
		t.Error(err)
	}
	if err := r.Snapshot(); err != nil {
		t.Error(err)
	}
	if err := r.Timestamp(); err != nil {
		t.Error(err)
	}
	if err := r.Commit(); err != nil {
		t.Error(err)
	}
}

func TestConcurrentAccessNewFromEnv(t *testing.T) {
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tufObj, err := NewFromEnv(context.Background())
			if err != nil {
				t.Errorf("Failed to construct NewFromEnv: %s", err)
			}
			if tufObj == nil {
				t.Error("Got back nil tufObj")
			}
			time.Sleep(1 * time.Second)
		}()
	}
	wg.Wait()
	resetForTests()
}

func TestConcurrentAccessInitialize(t *testing.T) {
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := Initialize(context.Background(), DefaultRemoteRoot, nil)
			if err != nil {
				t.Errorf("Failed to construct NewFromEnv: %s", err)
			}
			time.Sleep(1 * time.Second)
		}()
	}
	wg.Wait()
	resetForTests()
}

// Test to validate that sigstore TUF client can cache targets that
// are located in sub-folders.
func TestTargetsSubfolder(t *testing.T) {
	ctx := context.Background()
	// Create a remote repository.
	td := t.TempDir()
	remote, r := newTufCustomRepo(t, td, "foo")
	newTarget := "subfolder/fooNew.txt"
	addNewCustomTarget(t, td, r, map[string]string{newTarget: "newdata"})

	// Serve remote repository.
	s := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(td, "repository"))))
	defer s.Close()

	// Initialize with custom root.
	tufRoot := t.TempDir()
	// Set the TUF_ROOT so we don't interact with other tests and local TUF roots.
	t.Setenv("TUF_ROOT", tufRoot)
	meta, err := remote.GetMeta()
	if err != nil {
		t.Error(err)
	}
	rootBytes, ok := meta["root.json"]
	if !ok {
		t.Error(err)
	}

	if err := Initialize(ctx, s.URL, rootBytes); err != nil {
		t.Error(err)
	}

	defer resetForTests()

	tuf, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkTargetsAndMeta(t, tuf, []string{newTarget})
}

func Test_remoteFromMirror(t *testing.T) {
	// test GCS mirror
	mirror := "test-bucket"
	_, err := remoteFromMirror(mirror)
	if err != nil {
		t.Fatalf("unexpected error with GCS mirror: %v", err)
	}

	// test HTTP mirror
	mirror = "https://tuf-repo-cdn.sigstage.dev"
	_, err = remoteFromMirror(mirror)
	if err != nil {
		t.Fatalf("unexpected error with GCS mirror: %v", err)
	}

	// test local mirror
	tufRoot := t.TempDir()
	os.Mkdir(fmt.Sprintf("%s/targets", tufRoot), 0o0750)
	mirror = fmt.Sprintf("file://%s", tufRoot)
	_, err = remoteFromMirror(mirror)
	if err != nil {
		t.Fatalf("unexpected error with GCS mirror: %v", err)
	}
}
