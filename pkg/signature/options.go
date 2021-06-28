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

package signature

import (
	"context"
	"crypto"
	"crypto/rsa"
	"io"
)

// SignerOption configures a Signer.
type SignerOption interface {
	ApplySigner(s *SignRequest)
}

// VerifierOption configures a Verifier.
type VerifierOption interface {
	ApplyVerifier(v *VerifyRequest)
}

// Option configures a Signer or a Verifier.
type Option interface {
	SignerOption
	VerifierOption
}

// Both Signer and Verifier Options

// WithContext specifies the context under which the signing or verification should occur
func WithContext(ctx context.Context) Option {
	return withContext{ctx}
}

type withContext struct {
	ctx context.Context
}

func (w withContext) ApplySigner(s *SignRequest) {
	s.Ctx = w.ctx
}

func (w withContext) ApplyVerifier(v *VerifyRequest) {
	v.Ctx = w.ctx
}

// WithDigest specifies the digest to be used when generating or verifying the signature,
// as well as the hash function used to compute the digest
//
// If omitted during signing, the digest will be computed using the hash function
// configured
func WithDigest(digest []byte, hashFunc crypto.Hash) Option {
	return withDigest{digest, hashFunc}
}

type withDigest struct {
	digest   []byte
	hashFunc crypto.Hash
}

func (w withDigest) ApplySigner(s *SignRequest) {
	s.Digest = w.digest
	s.HashFunc = w.hashFunc
}

func (w withDigest) ApplyVerifier(v *VerifyRequest) {
	v.Digest = w.digest
	v.HashFunc = w.hashFunc
}

// Signing-only options

// WithRand sets the random number generator to be used when signing a message.
func WithRand(rand io.Reader) SignerOption {
	return withRand{rand}
}

type withRand struct {
	rand io.Reader
}

func (w withRand) ApplySigner(s *SignRequest) {
	s.Rand = w.rand
}

// withPSSOptions sets the required PSS options for using the RSA Signer or Verifier
func withPSSOptions(opts *rsa.PSSOptions) Option {
	return withPSSOptionsStruct{opts}
}

type withPSSOptionsStruct struct {
	opts *rsa.PSSOptions
}

func (w withPSSOptionsStruct) ApplySigner(s *SignRequest) {
	s.PSSOpts = w.opts
}

func (w withPSSOptionsStruct) ApplyVerifier(v *VerifyRequest) {
	v.PSSOpts = w.opts
}
