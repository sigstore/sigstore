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

// Package common has common code between sigstore and your plugin.
// using the github.com/hashicorp/go-plugin framework.
package common

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"log/slog"
	"net/rpc"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// Some of our interface functions don't return an error (e.g., SupportedAlgorithms),
// but our communication to the plugin may still error,
// so in the RPC functions we panic instead of returning the error.

type SignerVerifierRPC struct {
	client *rpc.Client
}

type SignerVerifierRPCServer struct {
	Impl SignerVerifier
}

// SupportedAlgorithmsArgs contains the args for SupportedAlgorithms().
type SupportedAlgorithmsArgs struct {
}

// SupportedAlgorithmsResp contains the return values for SuuportedAlgorithms().
type SupportedAlgorithmsResp struct {
	SupportedAlgorithms []string
}

// SupportedAlgorithms retrieves a list of supported algorithms.
func (s *SignerVerifierRPCServer) SupportedAlgorithms(_ *SupportedAlgorithmsArgs, resp *SupportedAlgorithmsResp) error {
	resp.SupportedAlgorithms = s.Impl.SupportedAlgorithms()
	return nil
}

// SupportedAlgorithms returns a list of supported algorithms.
func (c *SignerVerifierRPC) SupportedAlgorithms() []string {
	args := SupportedAlgorithmsArgs{}
	var resp SupportedAlgorithmsResp
	if err := c.client.Call("Plugin.SupportedAlgorithms", args, &resp); err != nil {
		panic(err)
	}
	return resp.SupportedAlgorithms
}

// DefaultAlgorithmArgs contains the args for DefaultAlgorithm().
type DefaultAlgorithmArgs struct {
}

// DefaultAlgorithmResp contains the return values for SuuportedAlgorithms().
type DefaultAlgorithmResp struct {
	DefaultAlgorithm string
}

// DefaultAlgorithm returns the default algorithm for the signer.
func (s *SignerVerifierRPCServer) DefaultAlgorithm(args *DefaultAlgorithmArgs, resp *DefaultAlgorithmResp) error {
	resp.DefaultAlgorithm = s.Impl.DefaultAlgorithm()
	return nil
}

// DefaultAlgorithm returns the default algorithm for the signer.
func (c *SignerVerifierRPC) DefaultAlgorithm() string {
	args := DefaultAlgorithmArgs{}
	var resp DefaultAlgorithmResp
	if err := c.client.Call("Plugin.DefaultAlgorithm", args, &resp); err != nil {
		panic(err)
	}
	return resp.DefaultAlgorithm
}

// CreateKeyArgs contains the args for CreateKey().
type CreateKeyArgs struct {
	// Ctx       context.Context
	Algorithm string
}

// CreateKeyResp contains the return values for CreateKey().
type CreateKeyResp struct {
	PublicKey PublicKeyGobWrapper
}

// CreateKey returns a crypto.PublicKey.
func (s *SignerVerifierRPCServer) CreateKey(args CreateKeyArgs, resp *CreateKeyResp) error {
	pubKey, err := s.Impl.CreateKey(context.TODO(), args.Algorithm)
	if err != nil {
		return err
	}
	resp.PublicKey = PublicKeyGobWrapper{PublicKey: pubKey}
	return nil
}

// CreateKey returns a crypto.PublicKey.
func (c *SignerVerifierRPC) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	args := CreateKeyArgs{
		// Ctx:       ctx,
		Algorithm: algorithm,
	}
	var resp CreateKeyResp
	if err := c.client.Call("Plugin.CreateKey", args, &resp); err != nil {
		return nil, err
	}
	return resp.PublicKey.PublicKey, nil
}

// SignMessageArgs cotnains the args for SignMessage().
type SignMessageArgs struct {
	Message IOReaderGobWrapper

	Opts []signature.SignOption
}

// SignMessageResp contains the return values for SignMessage().
type SignMessageResp struct {
	Signature []byte
}

// SignMessage signs the provided message.
func (s *SignerVerifierRPCServer) SignMessage(args SignMessageArgs, resp *SignMessageResp) error {
	var digest []byte
	var signerOpts crypto.SignerOpts
	for _, opt := range args.Opts {
		slog.Info("OPTS!")
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
		slog.Info("opts", "digest", digest)
	}
	if signerOpts != nil {
		slog.Info("opts", "hf", signerOpts.HashFunc().String())
	}

	signature, err := s.Impl.SignMessage(args.Message, args.Opts...)
	if err != nil {
		return err
	}
	resp.Signature = signature
	return nil
}

// SignMessage signs the provided message.
func (c *SignerVerifierRPC) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	// first compute the sum locally before transmitting,
	// then send that digest to be signed.
	// hashFunc := sha256.New()
	// if opts !
	// if _, err := io.Copy(hashFunc, message); err != nil {
	// 	return nil, err
	// }
	// digest := hashFunc.Sum(nil)

	// the internal cosign type cosign.HashReader is not accessable to be serialized,
	// so we instead use our IOReaderGobWrapper
	wrappedMessage := IOReaderGobWrapper{Reader: message}
	opts = append(opts, options.WithDigest([]byte("abc123")))
	opts = append(opts, options.WithHash(crypto.SHA224))
	args := SignMessageArgs{
		Message: wrappedMessage,
		Opts:    opts,
	}
	var resp SignMessageResp
	if err := c.client.Call("Plugin.SignMessage", args, &resp); err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

// VerifySignatureyArgs contains the args for VerifySignature().
type VerifySignatureArgs struct {
	Signature io.Reader
	Message   io.Reader
	Opts      []signature.VerifyOption
}

// VerifySignatureyResp contains the return values for VerifySignature().
type VerifySignatureResp struct {
}

// SignMessage signs the provided message.
func (s *SignerVerifierRPCServer) VerifySignature(args VerifySignatureArgs, resp *VerifySignatureResp) error {
	if err := s.Impl.VerifySignature(args.Message, args.Signature, args.Opts...); err != nil {
		return err
	}
	return nil
}

// VerifySignature verifies the signature for the given message.
func (c *SignerVerifierRPC) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	args := VerifySignatureArgs{
		Opts: opts,
	}
	var resp VerifySignatureResp
	if err := c.client.Call("Plugin.VerifySignature", args, &resp); err != nil {
		return err
	}
	return nil
}

// PublicKeyArgs cotnains the args for PublicKey().
type PublicKeyArgs struct {
	Opts []signature.PublicKeyOption
}

// PublicKeyResp contains the return values for PublicKey().
type PublicKeyResp struct {
	PublicKey PublicKeyGobWrapper
}

// SignMessage signs the provided message.
func (s *SignerVerifierRPCServer) PublicKey(args PublicKeyArgs, resp *PublicKeyResp) error {
	pubKey, err := s.Impl.PublicKey(args.Opts...)
	if err != nil {
		return err
	}
	// crypto.PublicKey is not gob encodeable, so we wrap it in our PublicKeyGobWrapper.
	resp.PublicKey = PublicKeyGobWrapper{PublicKey: pubKey}
	return nil
}

// SignMessage signs the provided message.
func (c *SignerVerifierRPC) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	args := PublicKeyArgs{
		Opts: opts,
	}
	var resp PublicKeyResp
	if err := c.client.Call("Plugin.PublicKey", args, &resp); err != nil {
		return nil, err
	}
	return resp.PublicKey.PublicKey, nil
}

// CryptoSignerArgs contains the args for CryptoSigner().
type CryptoSignerArgs struct {
	// Ctx     context.Context
	// ErrFunc func(error)
}

// CryptoSignerResp contains the return values for CryptoSigner().
type CryptoSignerResp struct {
	// Signer     CryptoSignerGobWrapper
	// SignerOpts crypto.SignerOpts
}

// CryptoSigner is not implemented becuase it is not needed by cosign CLI.
func (s *SignerVerifierRPCServer) CryptoSigner(args CryptoSignerArgs, resp *CryptoSignerResp) error {
	return fmt.Errorf("%w: CryptoSigner is not implemented for the plugin", ErrorNotImplemented)
	// signer, signerOpts, err := s.Impl.CryptoSigner(context.Background(), func(err error) { slog.Error((err.Error())) })
	// if err != nil {
	// 	return err
	// }
	// resp.Signer = CryptoSignerGobWrapper{Signer: signer}
	// resp.SignerOpts = signerOpts
	return nil
}

// CryptoSigner is not implemented becuase it is not needed by cosign CLI.
func (c *SignerVerifierRPC) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	return nil, nil, fmt.Errorf("%w: CryptoSigner is not implemented for the plugin", ErrorNotImplemented)
	// args := CryptoSignerArgs{}
	// var resp CryptoSignerResp
	//
	//	if err := c.client.Call("Plugin.CryptoSigner", args, &resp); err != nil {
	//		return nil, nil, err
	//	}
	//
	// return resp.Signer, resp.SignerOpts, nil
}
