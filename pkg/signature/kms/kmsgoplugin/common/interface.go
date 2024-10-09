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
	"io"
	"log/slog"
	"net/rpc"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"

	"github.com/hashicorp/go-plugin"
)

// Some of our interface functions don't return an error, but our communication to the plugin may still error,
// so we panic instead of returning the error.

func init() {
	// gob.Register(ecdsa.PublicKey{})
	// gob.Register(elliptic.P256())
}

const (
	DefaultPluginBinaryRelativePath = "./sigstore-kms-go-plugin"
	PluginPathEnvKey                = "SIGSTORE_GO_PLUGIN_PATH"
	KMSPluginName                   = "sigstore-kms-plugin"
)

var (
	// HandshakeConfig is the configuration for a proper handshake between client and server of the plugin.
	// This is not authentication, but identification.
	HandshakeConfig = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "SIGSTORE_KMS_PLUGIN",
		MagicCookieValue: "sigstore",
	}

	_ SignerVerifier = &SignerVerifierRPC{}
	// _ kms.SignerVerifier = (*SignerVerifierRPC)(nil)
)

// SignerVerifier wraps around kms.SignerVerifier
type SignerVerifier interface {
	kms.SignerVerifier
}

type SignerVerifierRPC struct {
	client *rpc.Client
}

type SignerVerifierRPCServer struct {
	Impl SignerVerifier
}

type SignerVerifierPlugin struct {
	Impl SignerVerifier
}

func (p *SignerVerifierPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &SignerVerifierRPCServer{Impl: p.Impl}, nil
}

func (SignerVerifierPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &SignerVerifierRPC{client: c}, nil
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
	// PublicKeyPEM is our marhsalled crypto.PublicKey, becuase that type is not serializable for use with go-plugin.
	PublicKeyPEM []byte
	Error        error
}

// CreateKey returns a crypto.PublicKey.
func (s *SignerVerifierRPCServer) CreateKey(args CreateKeyArgs, resp *CreateKeyResp) error {
	pubKey, err := s.Impl.CreateKey(context.TODO(), args.Algorithm)
	resp.Error = err
	pubKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		return err
	}
	resp.PublicKeyPEM = pubKeyPEM
	return resp.Error
}

// CreateKey returns a crypto.PublicKey.
func (c *SignerVerifierRPC) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	args := CreateKeyArgs{
		// Ctx:       ctx,
		Algorithm: algorithm,
	}
	var resp CreateKeyResp
	if err := c.client.Call("Plugin.CreateKey", args, &resp); err != nil {
		slog.Error("create", "res", resp.PublicKeyPEM)
		panic(err)
	}
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(resp.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return pubKey, resp.Error
}

// SignMessageArgs cotnains the args for SignMessage().
type SignMessageArgs struct {
	Message io.Reader
	Opts    []signature.SignOption
}

// SignMessageResp contains the return values for SignMessage().
type SignMessageResp struct {
	Signature []byte
	Error     error
}

// SignMessage signs the provided message.
func (s *SignerVerifierRPCServer) SignMessage(args SignMessageArgs, resp *SignMessageResp) error {
	resp.Signature, resp.Error = s.Impl.SignMessage(args.Message, args.Opts...)
	return resp.Error
}

// SignMessage signs the provided message.
func (c *SignerVerifierRPC) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	args := SignMessageArgs{
		Message: message,
		Opts:    opts,
	}
	var resp SignMessageResp
	if err := c.client.Call("Plugin.SignMessage", args, &resp); err != nil {
		panic(err)
	}
	return resp.Signature, resp.Error
}

// VerifySignatureyArgs contains the args for VerifySignature().
type VerifySignatureArgs struct {
	Signature io.Reader
	Message   io.Reader
	Opts      []signature.VerifyOption
}

// VerifySignatureyResp contains the return values for VerifySignature().
type VerifySignatureResp struct {
	Error error
}

// SignMessage signs the provided message.
func (s *SignerVerifierRPCServer) VerifySignature(args VerifySignatureArgs, resp *VerifySignatureResp) error {
	resp.Error = s.Impl.VerifySignature(args.Message, args.Signature, args.Opts...)
	return resp.Error
}

// VerifySignature verifies the signature for the given message.
func (c *SignerVerifierRPC) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	args := VerifySignatureArgs{
		Opts: opts,
	}
	var resp VerifySignatureResp
	if err := c.client.Call("Plugin.VerifySignature", args, &resp); err != nil {
		panic(err)
	}
	return resp.Error
}

// PublicKeyArgs cotnains the args for PublicKey().
type PublicKeyArgs struct {
	Opts []signature.PublicKeyOption
}

// PublicKeyResp contains the return values for PublicKey().
type PublicKeyResp struct {
	// PublicKeyPEM is our marhsalled crypto.PublicKey, becuase that type is not serializable for use with go-plugin.
	PublicKeyPEM []byte
	Error        error
}

// SignMessage signs the provided message.
func (s *SignerVerifierRPCServer) PublicKey(args PublicKeyArgs, resp *PublicKeyResp) error {
	pubKey, err := s.Impl.PublicKey(args.Opts...)
	resp.Error = err
	pubKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		return err
	}
	resp.PublicKeyPEM = pubKeyPEM
	return resp.Error
}

// SignMessage signs the provided message.
func (c *SignerVerifierRPC) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	args := PublicKeyArgs{
		Opts: opts,
	}
	var resp PublicKeyResp
	if err := c.client.Call("Plugin.PublicKey", args, &resp); err != nil {
		panic(err)
	}
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(resp.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return pubKey, resp.Error
}

// CryptoSignerArgs contains the args for CryptoSigner().
type CryptoSignerArgs struct {
	// Ctx     context.Context
	ErrFunc func(error)
}

// CryptoSignerResp contains the return values for CryptoSigner().
type CryptoSignerResp struct {
	Signer     crypto.Signer
	SignerOpts crypto.SignerOpts
	Error      error
}

func (s *SignerVerifierRPCServer) CryptoSigner(args CryptoSignerArgs, resp *CryptoSignerResp) error {
	resp.Signer, resp.SignerOpts, resp.Error = s.Impl.CryptoSigner(context.TODO(), args.ErrFunc)
	return resp.Error
}

func (c *SignerVerifierRPC) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	args := CryptoSignerArgs{
		// Ctx:     ctx,
		ErrFunc: errFunc,
	}
	var resp CryptoSignerResp
	if err := c.client.Call("Plugin.CryptoSigner", args, &resp); err != nil {
		panic(err)
	}
	return resp.Signer, resp.SignerOpts, resp.Error
}
