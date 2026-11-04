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

package gcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"hash/crc32"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestParseReference(t *testing.T) {
	tests := []struct {
		in             string
		wantProjectID  string
		wantLocationID string
		wantKeyRing    string
		wantKeyName    string
		wantKeyVersion string
		wantErr        bool
	}{
		{
			in:             "gcpkms://projects/pp/locations/ll/keyRings/rr/cryptoKeys/kk",
			wantProjectID:  "pp",
			wantLocationID: "ll",
			wantKeyRing:    "rr",
			wantKeyName:    "kk",
			wantErr:        false,
		},
		{
			in:             "gcpkms://projects/pp/locations/ll/keyRings/rr/cryptoKeys/kk/versions/1",
			wantProjectID:  "pp",
			wantLocationID: "ll",
			wantKeyRing:    "rr",
			wantKeyName:    "kk",
			wantKeyVersion: "1",
			wantErr:        false,
		},
		{
			in:             "gcpkms://projects/pp/locations/ll/keyRings/rr/cryptoKeys/kk/cryptoKeyVersions/1",
			wantProjectID:  "pp",
			wantLocationID: "ll",
			wantKeyRing:    "rr",
			wantKeyName:    "kk",
			wantKeyVersion: "1",
			wantErr:        false,
		},
		{
			in:      "gcpkms://projects/p1/p2/locations/l1/l2/keyRings/r1/r2/cryptoKeys/k1/k2",
			wantErr: true,
		},
		{
			in:      "foo://bar",
			wantErr: true,
		},
		{
			in:      "",
			wantErr: true,
		},
		{
			in:      "gcpkms://projects/p1/p2/locations/l1/l2/keyRings/r1/r2/cryptoKeys/k1/versions",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			gotProjectID, gotLocationID, gotKeyRing, gotKeyName, gotKeyVersion, err := parseReference(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotProjectID != tt.wantProjectID {
				t.Errorf("parseReference() gotProjectID = %v, want %v", gotProjectID, tt.wantProjectID)
			}
			if gotLocationID != tt.wantLocationID {
				t.Errorf("parseReference() gotLocationID = %v, want %v", gotLocationID, tt.wantLocationID)
			}
			if gotKeyRing != tt.wantKeyRing {
				t.Errorf("parseReference() gotKeyRing = %v, want %v", gotKeyRing, tt.wantKeyRing)
			}
			if gotKeyName != tt.wantKeyName {
				t.Errorf("parseReference() gotKeyName = %v, want %v", gotKeyName, tt.wantKeyName)
			}
			if gotKeyVersion != tt.wantKeyVersion {
				t.Errorf("parseReference() gotKeyVersion = %v, want %v", gotKeyVersion, tt.wantKeyVersion)
			}
		})
	}
}

func TestOptionsWork(_ *testing.T) {
	// Check that we can pass options into LoadSignerVerifier
	// (this is mostly a compile-time check)
	ts := oauth2.StaticTokenSource(&oauth2.Token{})
	LoadSignerVerifier(context.Background(), "gcpkms://projects/a-project/locations/global/keyRings/a-keyring/cryptoKeys/key-name", option.WithTokenSource(ts))
}

type fakeKMSServer struct {
	kmspb.UnimplementedKeyManagementServiceServer

	privKey *ecdsa.PrivateKey
	pubPEM  string

	mu    sync.Mutex
	delay time.Duration
	err   error

	getCryptoKeyCalls          atomic.Int64
	getCryptoKeyVersionCalls   atomic.Int64
	listCryptoKeyVersionsCalls atomic.Int64
	getPublicKeyCalls          atomic.Int64
	asymmetricSignCalls        atomic.Int64
}

func newFakeKMSServer(t *testing.T) (*fakeKMSServer, *grpc.ClientConn) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() failed: %v", err)
	}
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(privKey.Public())
	if err != nil {
		t.Fatalf("MarshalPublicKeyToPEM() failed: %v", err)
	}

	srv := &fakeKMSServer{
		privKey: privKey,
		pubPEM:  string(pubPEM),
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	grpcServer := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(grpcServer, srv)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return srv, conn
}

func (f *fakeKMSServer) resetCounts() {
	f.getCryptoKeyCalls.Store(0)
	f.getCryptoKeyVersionCalls.Store(0)
	f.listCryptoKeyVersionsCalls.Store(0)
	f.getPublicKeyCalls.Store(0)
	f.asymmetricSignCalls.Store(0)
}

func (f *fakeKMSServer) setBehavior(delay time.Duration, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delay = delay
	f.err = err
}

func (f *fakeKMSServer) checkBehavior() error {
	f.mu.Lock()
	delay := f.delay
	err := f.err
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	return err
}

func (f *fakeKMSServer) GetCryptoKey(_ context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	f.getCryptoKeyCalls.Add(1)
	if err := f.checkBehavior(); err != nil {
		return nil, err
	}
	return &kmspb.CryptoKey{
		Name:    req.GetName(),
		Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
	}, nil
}

func (f *fakeKMSServer) GetCryptoKeyVersion(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	f.getCryptoKeyVersionCalls.Add(1)
	if err := f.checkBehavior(); err != nil {
		return nil, err
	}
	return &kmspb.CryptoKeyVersion{
		Name:      req.GetName(),
		Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		State:     kmspb.CryptoKeyVersion_ENABLED,
	}, nil
}

func (f *fakeKMSServer) ListCryptoKeyVersions(_ context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	f.listCryptoKeyVersionsCalls.Add(1)
	if err := f.checkBehavior(); err != nil {
		return nil, err
	}
	return &kmspb.ListCryptoKeyVersionsResponse{
		CryptoKeyVersions: []*kmspb.CryptoKeyVersion{
			{
				Name:      req.GetParent() + "/cryptoKeyVersions/1",
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
				State:     kmspb.CryptoKeyVersion_ENABLED,
			},
		},
	}, nil
}

func (f *fakeKMSServer) GetPublicKey(_ context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	f.getPublicKeyCalls.Add(1)
	if err := f.checkBehavior(); err != nil {
		return nil, err
	}
	return &kmspb.PublicKey{
		Name:      req.GetName(),
		Pem:       f.pubPEM,
		Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
	}, nil
}

func (f *fakeKMSServer) AsymmetricSign(_ context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	f.asymmetricSignCalls.Add(1)
	sig, err := ecdsa.SignASN1(rand.Reader, f.privKey, req.GetDigest().GetSha256())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "signing failed: %v", err)
	}
	crc := crc32.Checksum(sig, crc32.MakeTable(crc32.Castagnoli))
	return &kmspb.AsymmetricSignResponse{
		Name:                 req.GetName(),
		Signature:            sig,
		SignatureCrc32C:      wrapperspb.Int64(int64(crc)),
		VerifiedDigestCrc32C: true,
	}, nil
}

func TestVersionedKeyPrimingAndNoTTL(t *testing.T) {
	srv, conn := newFakeKMSServer(t)

	ref := "gcpkms://projects/pp/locations/ll/keyRings/rr/cryptoKeys/kk/cryptoKeyVersions/1"
	sv, err := LoadSignerVerifier(context.Background(), ref, option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("LoadSignerVerifier() unexpected error: %v", err)
	}

	// Construction should prime the cache once using the versioned path.
	if got := srv.getCryptoKeyCalls.Load(); got != 1 {
		t.Errorf("GetCryptoKey calls after priming = %d, want 1", got)
	}
	if got := srv.getCryptoKeyVersionCalls.Load(); got != 1 {
		t.Errorf("GetCryptoKeyVersion calls after priming = %d, want 1", got)
	}
	if got := srv.listCryptoKeyVersionsCalls.Load(); got != 0 {
		t.Errorf("ListCryptoKeyVersions calls after priming = %d, want 0", got)
	}
	if got := srv.getPublicKeyCalls.Load(); got != 1 {
		t.Errorf("GetPublicKey calls after priming = %d, want 1", got)
	}

	item := sv.client.kvCache.Get(cacheKey)
	if item == nil {
		t.Fatal("expected cache item to be populated after priming, got nil")
	}
	if got := item.TTL(); got != ttlcache.NoTTL {
		t.Errorf("cached item TTL = %v, want %v (NoTTL)", got, ttlcache.NoTTL)
	}
	if !item.ExpiresAt().IsZero() {
		t.Errorf("cached item ExpiresAt = %v, want zero time for pinned version", item.ExpiresAt())
	}

	// Subsequent SignMessage, PublicKey, and VerifySignature calls should not make any KMS read RPCs.
	msg := []byte("hello sigstore")
	for i := 0; i < 5; i++ {
		sig, err := sv.SignMessage(bytes.NewReader(msg))
		if err != nil {
			t.Fatalf("SignMessage() iteration %d unexpected error: %v", i, err)
		}
		if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
			t.Fatalf("VerifySignature() iteration %d unexpected error: %v", i, err)
		}
		if _, err := sv.PublicKey(); err != nil {
			t.Fatalf("PublicKey() iteration %d unexpected error: %v", i, err)
		}
	}

	if got := srv.getCryptoKeyCalls.Load(); got != 1 {
		t.Errorf("GetCryptoKey calls after signing = %d, want 1", got)
	}
	if got := srv.getCryptoKeyVersionCalls.Load(); got != 1 {
		t.Errorf("GetCryptoKeyVersion calls after signing = %d, want 1", got)
	}
	if got := srv.getPublicKeyCalls.Load(); got != 1 {
		t.Errorf("GetPublicKey calls after signing = %d, want 1", got)
	}
	if got := srv.asymmetricSignCalls.Load(); got != 5 {
		t.Errorf("AsymmetricSign calls = %d, want 5", got)
	}
}

func TestUnversionedKeySingleflightCoalescesConcurrentMisses(t *testing.T) {
	srv, conn := newFakeKMSServer(t)

	ref := "gcpkms://projects/pp/locations/ll/keyRings/rr/cryptoKeys/kk"
	sv, err := LoadSignerVerifier(context.Background(), ref, option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("LoadSignerVerifier() unexpected error: %v", err)
	}

	if got := srv.getCryptoKeyCalls.Load(); got != 1 {
		t.Errorf("GetCryptoKey calls after priming = %d, want 1", got)
	}
	if got := srv.listCryptoKeyVersionsCalls.Load(); got != 1 {
		t.Errorf("ListCryptoKeyVersions calls after priming = %d, want 1", got)
	}
	if got := srv.getPublicKeyCalls.Load(); got != 1 {
		t.Errorf("GetPublicKey calls after priming = %d, want 1", got)
	}

	item := sv.client.kvCache.Get(cacheKey)
	if item == nil {
		t.Fatal("expected cache item to be populated after priming, got nil")
	}
	if got := item.TTL(); got != 300*time.Second {
		t.Errorf("cached item TTL = %v, want 300s", got)
	}

	// Simulate TTL expiry and a burst of concurrent SignMessage and PublicKey requests.
	sv.client.kvCache.Delete(cacheKey)
	srv.resetCounts()
	srv.setBehavior(25*time.Millisecond, nil)

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				_, err := sv.SignMessage(bytes.NewReader([]byte("concurrent payload")))
				errs <- err
			} else {
				_, err := sv.PublicKey()
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("concurrent operation returned unexpected error: %v", err)
		}
	}

	// All 32 concurrent cache misses must coalesce into a single KMS metadata reload.
	if got := srv.getCryptoKeyCalls.Load(); got != 1 {
		t.Errorf("GetCryptoKey calls under %d concurrent misses = %d, want 1", workers, got)
	}
	if got := srv.listCryptoKeyVersionsCalls.Load(); got != 1 {
		t.Errorf("ListCryptoKeyVersions calls under %d concurrent misses = %d, want 1", workers, got)
	}
	if got := srv.getPublicKeyCalls.Load(); got != 1 {
		t.Errorf("GetPublicKey calls under %d concurrent misses = %d, want 1", workers, got)
	}
	if got := srv.asymmetricSignCalls.Load(); got != workers/2 {
		t.Errorf("AsymmetricSign calls = %d, want %d", got, workers/2)
	}
}

func TestSingleflightErrorPropagationAndRecovery(t *testing.T) {
	srv, conn := newFakeKMSServer(t)

	ref := "gcpkms://projects/pp/locations/ll/keyRings/rr/cryptoKeys/kk"
	sv, err := LoadSignerVerifier(context.Background(), ref, option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("LoadSignerVerifier() unexpected error: %v", err)
	}

	// Evict the cached entry and configure the server to fail KMS metadata lookups.
	sv.client.kvCache.Delete(cacheKey)
	srv.resetCounts()
	srv.setBehavior(25*time.Millisecond, status.Error(codes.ResourceExhausted, "quota exceeded"))

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				_, err := sv.SignMessage(bytes.NewReader([]byte("payload")))
				errs <- err
			} else {
				_, err := sv.PublicKey()
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err == nil {
			t.Error("expected non-nil error from failed KMS lookup, got nil")
		}
	}
	if got := srv.getCryptoKeyCalls.Load(); got != 1 {
		t.Errorf("GetCryptoKey calls during coalesced failure = %d, want 1", got)
	}

	// Once KMS recovers, the next call should reload and populate the cache cleanly.
	srv.setBehavior(0, nil)
	sig, err := sv.SignMessage(bytes.NewReader([]byte("recovered payload")))
	if err != nil {
		t.Fatalf("SignMessage() after recovery unexpected error: %v", err)
	}
	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte("recovered payload"))); err != nil {
		t.Fatalf("VerifySignature() after recovery unexpected error: %v", err)
	}
}
