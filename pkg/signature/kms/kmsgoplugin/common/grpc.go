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
	"bytes"
	"crypto"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	kmsproto "github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common/proto"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"google.golang.org/grpc/metadata"

	"context"
)

// GRPCClient is an implementation of Greeter that talks over RPC.
type GRPCClient struct {
	KMSGoPluginSignerVerifier
	client     kmsproto.KMSServiceClient
	SignerOpts crypto.SignerOpts
}

func (c *GRPCClient) SetState(state *KMSGoPluginState) {
	hashFuncData, err := GobEncode(state.HashFunc)
	if err != nil {
		panic(fmt.Errorf("%w: %w", ErrorUnreturnableKMSGRPC, err))
	}
	if _, err := c.client.SetState(context.TODO(), &kmsproto.SetStateRequest{
		KeyResourceId: state.KeyResourceID,
		HashFuncData:  hashFuncData,
	}); err != nil {
		panic(fmt.Errorf("%w: %w", ErrorUnreturnableKMSGRPC, err))
	}

}

func (s *GRPCServer) SetState(ctx context.Context, req *kmsproto.SetStateRequest) (*kmsproto.SetStateResponse, error) {
	var hashFunc crypto.Hash
	err := GobDecode(req.HashFuncData, &hashFunc)
	if err != nil {
		return nil, err
	}
	s.Impl.SetState(
		&KMSGoPluginState{
			KeyResourceID: req.KeyResourceId,
			HashFunc:      hashFunc,
		},
	)
	return &kmsproto.SetStateResponse{}, nil
}

func (c *GRPCClient) SupportedAlgorithms() []string {
	resp, err := c.client.SupportedAlgorithms(context.TODO(), &kmsproto.SupportedAlgorithmsRequest{})
	if err != nil {
		panic(fmt.Errorf("%w: %w", ErrorUnreturnableKMSGRPC, err))
	}
	return resp.SupportedAlgorithms
}

func (s *GRPCServer) SupportedAlgorithms(ctx context.Context, req *kmsproto.SupportedAlgorithmsRequest) (*kmsproto.SupportedAlgorithmsResponse, error) {
	val := s.Impl.SupportedAlgorithms()
	return &kmsproto.SupportedAlgorithmsResponse{SupportedAlgorithms: val}, nil
}

func (c *GRPCClient) DefaultAlgorithm() string {
	resp, err := c.client.DefaultAlgorithm(context.TODO(), &kmsproto.DefaultAlgorithmRequest{})
	if err != nil {
		panic(fmt.Errorf("%w: %w", ErrorUnreturnableKMSGRPC, err))
	}
	return resp.DefaultAgorithm
}

func (s *GRPCServer) DefaultAlgorithm(ctx context.Context, req *kmsproto.DefaultAlgorithmRequest) (*kmsproto.DefaultAlgorithmResponse, error) {
	val := s.Impl.DefaultAlgorithm()
	return &kmsproto.DefaultAlgorithmResponse{DefaultAgorithm: val}, nil
}

func (c *GRPCClient) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	resp, err := c.client.CreateKey(ctx, &kmsproto.CreateKeyRequest{
		Algorithm: algorithm,
	})
	if err != nil {
		return nil, err
	}

	publicKeyWrapper := &PublicKeyGobWrapper{}
	if err := GobDecode(resp.PublicKeyData, publicKeyWrapper); err != nil {
		return nil, err
	}
	return publicKeyWrapper.PublicKey, nil
}

func (s *GRPCServer) CreateKey(ctx context.Context, req *kmsproto.CreateKeyRequest) (*kmsproto.CreateKeyResponse, error) {
	publicKey, err := s.Impl.CreateKey(ctx, req.Algorithm)
	if err != nil {
		return nil, err
	}
	wrappedPublicKey := PublicKeyGobWrapper{PublicKey: publicKey}
	publicKeyData, err := GobEncode(wrappedPublicKey)
	if err != nil {
		return nil, err
	}

	return &kmsproto.CreateKeyResponse{PublicKeyData: publicKeyData}, nil
}

// func extractMessageOptions[O *signature.SignOption | *signature.VerifyOption](defaultSignerOpts *crypto.SignerOpts, opts ...O) (*context.Context, *kmsproto.MessageOption, error) {

type SignVerifyOption interface {
	signature.SignOption
	signature.VerifyOption
}

func (c GRPCClient) extractMessageFromOpts(opts interface{}) (*context.Context, *kmsproto.MessageOption, error) {
	var ctx = context.TODO()
	var digestData []byte
	var signerOpts crypto.SignerOpts = c.SignerOpts

	switch opts := opts.(type) {
	case []signature.SignOption:
		for _, opt := range opts {
			opt.ApplyContext(&ctx)
			opt.ApplyDigest(&digestData)
			opt.ApplyCryptoSignerOpts(&signerOpts)
		}
	case []signature.VerifyOption:
		for _, opt := range opts {
			opt.ApplyContext(&ctx)
			opt.ApplyDigest(&digestData)
			opt.ApplyCryptoSignerOpts(&signerOpts)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported type: %v", opts)
	}

	var messageOption *kmsproto.MessageOption

	if len(digestData) != 0 || signerOpts != nil {
		messageOption = &kmsproto.MessageOption{}

		if len(digestData) != 0 {
			messageOption.DigestData = digestData
		}

		if signerOpts != nil {
			hashFuncData, err := json.Marshal(signerOpts.HashFunc())
			if err != nil {
				return nil, nil, err
			}
			messageOption.SignerOpts = &kmsproto.SignerOpts{
				HashFuncData: hashFuncData,
			}
		}
	}
	return &ctx, messageOption, nil
}

type CtxStruct struct {
	val string
}

type CtxKey string

var ctxKey = CtxKey("trace")

// SignMessage
func (c *GRPCClient) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	messageBytes, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}

	ctx, messageOption, err := c.extractMessageFromOpts(opts)
	if err != nil {
		return nil, err
	}

	signMessageRequest := &kmsproto.SignMessageRequest{
		Message: messageBytes,
	}
	if messageOption != nil {
		signMessageRequest.SignOptions = &kmsproto.SignOptions{
			MessageOption: messageOption,
		}
	}

	*ctx, _ = context.WithDeadline(*ctx, time.Now().Add(1*time.Minute))
	*ctx = context.WithValue(*ctx, ctxKey, "abc123")
	*ctx = metadata.NewOutgoingContext(
		*ctx,
		metadata.Pairs("key1", "val1", "key2", "val2"),
	)

	resp, err := c.client.SignMessage(*ctx, signMessageRequest)
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

// extractOptsFromMessage extracts the signature.[Sign|Verify]Option from the proto.Message.
// the caller will have to do a type assertion on the return value: exOpts, ok := exOptsInt.([]signature.SignOption).
func (s *GRPCServer) extractOptsFromMessage(messageOption *kmsproto.MessageOption) (interface{}, error) {
	if messageOption == nil {
		return nil, nil
	}
	opts := []interface{}{}
	digestData := messageOption.DigestData
	if len(digestData) != 0 {
		digest := digestData
		opts = append(opts, options.WithDigest(digest))
	}
	signerOpts := messageOption.SignerOpts
	if signerOpts != nil {
		hashFuncData := signerOpts.HashFuncData
		if len(hashFuncData) != 0 {
			var hashFunc crypto.Hash
			if err := json.Unmarshal(hashFuncData, &hashFunc); err != nil {
				return nil, err
			}
			opts = append(opts, options.WithHash(hashFunc))
		}
	}
	return opts, nil
}

func (s *GRPCServer) SignMessage(ctx context.Context, req *kmsproto.SignMessageRequest) (*kmsproto.SignMessageResponse, error) {
	messageReader := bytes.NewReader(req.Message)

	deadline, ok := ctx.Deadline()
	if ok {
		slog.Info("context", "now", time.Now(), "deadline", deadline, "diff", time.Until(deadline))
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		slog.Info("context", "md", md.Get("trace"))
	}
	ctxVal := ctx.Value(ctxKey)
	slog.Info("context", "val", ctxVal, "other", metadata.ValueFromIncomingContext(ctx, "key1"))

	opts := []signature.SignOption{}
	if req.SignOptions != nil {
		signOptions := req.SignOptions
		messageOption := signOptions.MessageOption
		exOptsInt, err := s.extractOptsFromMessage(messageOption)
		if err != nil {
			return nil, err
		}
		exOpts, ok := exOptsInt.([]signature.SignOption)
		if !ok {
			return nil, err
		}
		opts = exOpts
	}

	signature, err := s.Impl.SignMessage(messageReader, opts...)
	if err != nil {
		return nil, err
	}
	return &kmsproto.SignMessageResponse{Signature: signature}, nil
}

func (c *GRPCClient) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	signatureBytes, err := io.ReadAll(signature)
	if err != nil {
		return err
	}

	messageBytes, err := io.ReadAll(message)
	if err != nil {
		return err
	}

	context, messageOption, err := c.extractMessageFromOpts(opts)
	if err != nil {
		return err
	}

	verfySignatureRequest := &kmsproto.VerifySignatureRequest{
		Signature: signatureBytes,
		Message:   messageBytes,
	}
	if messageOption != nil {
		verfySignatureRequest.VerifyOptions = &kmsproto.VerifyOption{
			MessageOption: messageOption,
		}
	}

	if _, err := c.client.VerifySignature(*context, verfySignatureRequest); err != nil {
		return err
	}
	return nil
}

func (s *GRPCServer) VerifySignature(ctx context.Context, req *kmsproto.VerifySignatureRequest) (*kmsproto.VerifySignatureResponse, error) {
	signatureReader := bytes.NewReader(req.Signature)
	messageReader := bytes.NewReader(req.Message)

	opts := []signature.VerifyOption{}
	if req.VerifyOptions != nil {
		veifyOptions := req.VerifyOptions
		messageOption := veifyOptions.MessageOption
		exOptsInt, err := s.extractOptsFromMessage(messageOption)
		if err != nil {
			return nil, err
		}
		exOpts, ok := exOptsInt.([]signature.VerifyOption)
		if !ok {
			return nil, err
		}
		opts = exOpts
	}

	if err := s.Impl.VerifySignature(signatureReader, messageReader, opts...); err != nil {
		return nil, err
	}
	return &kmsproto.VerifySignatureResponse{}, nil
}

func (c *GRPCClient) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.TODO()

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}

	resp, err := c.client.PublicKey(ctx, &kmsproto.PublicKeyRequest{})
	if err != nil {
		return nil, err
	}

	publicKeyWrapper := &PublicKeyGobWrapper{}
	if err := GobDecode(resp.PublicKeyData, publicKeyWrapper); err != nil {
		return nil, err
	}
	return publicKeyWrapper.PublicKey, nil
}

func (s *GRPCServer) PublicKey(ctx context.Context, req *kmsproto.PublicKeyRequest) (*kmsproto.PublicKeyResponse, error) {
	opts := []signature.PublicKeyOption{
		options.WithContext(ctx),
	}
	publicKey, err := s.Impl.PublicKey(opts...)
	if err != nil {
		return nil, err
	}
	wrappedPublicKey := PublicKeyGobWrapper{PublicKey: publicKey}
	publicKeyData, err := GobEncode(wrappedPublicKey)
	if err != nil {
		return nil, err
	}
	return &kmsproto.PublicKeyResponse{PublicKeyData: publicKeyData}, nil
}

type CryptoSignerWrapper struct {
	crypto.Signer
	*GRPCClient
	errFunc func(error)
}

func (s CryptoSignerWrapper) Public() crypto.PublicKey {
	publicKey, err := s.GRPCClient.PublicKey()
	if err != nil {
		s.errFunc(err)
		panic(fmt.Errorf("%w:, %s", ErrorUnreturnableKMSGRPC, "CryptoSignerWrapper.Public()"))
	}
	return publicKey
}

func (s CryptoSignerWrapper) Sign(rand io.Reader, digest []byte, signerOpts crypto.SignerOpts) ([]byte, error) {
	emptyMessage := bytes.NewReader([]byte{})
	signOpts := []signature.SignOption{
		options.WithHash(signerOpts.HashFunc()),
	}
	signature, err := s.SignMessage(emptyMessage, signOpts...)
	if err != nil {
		s.errFunc(err)
		return nil, err
	}
	return signature, nil
}

func (c *GRPCClient) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	cryptoSigner := &CryptoSignerWrapper{GRPCClient: c, errFunc: errFunc}
	signerOpts := c.SignerOpts
	return cryptoSigner, signerOpts, nil
}

// GobEncode runs gob encoding. Example: GobEncode(WrappedPublickKey{pubkey}).
func GobEncode(source interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(source); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func GobDecode(data []byte, target interface{}) error {
	return gob.NewDecoder(bytes.NewBuffer(data)).Decode(target)
}
