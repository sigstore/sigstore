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

	"github.com/davecgh/go-spew/spew"
	"github.com/sigstore/sigstore/pkg/signature"
	kmsproto "github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common/proto"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"google.golang.org/protobuf/types/known/anypb"

	"context"
)

// GRPCClient is an implementation of Greeter that talks over RPC.
type GRPCClient struct {
	SignerVerifier
	client     kmsproto.KMSServiceClient
	SignerOpts crypto.SignerOpts
}

func (c *GRPCClient) SupportedAlgorithms() []string {
	resp, err := c.client.SupportedAlgorithms(context.Background(), &kmsproto.SupportedAlgorithmsRequest{})
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
	resp, err := c.client.DefaultAlgorithm(context.Background(), &kmsproto.DefaultAlgorithmRequest{})
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
	var publicKeyWrapper PublicKeyGobWrapper
	if err := publicKeyWrapper.GobDecode(resp.PublicKeyData); err != nil {
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

func (c *GRPCClient) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	messageBytes, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}

	var digestData []byte
	var signerOpts crypto.SignerOpts = c.SignerOpts
	for _, opt := range opts {
		opt.ApplyDigest(&digestData)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	var signOptions *kmsproto.SignOptions
	if len(digestData) != 0 || signerOpts != nil {
		signOptions = &kmsproto.SignOptions{
			MessageOption: &kmsproto.MessageOption{},
		}
	}

	if len(digestData) != 0 {
		signOptions.MessageOption.DigestData = digestData
	}

	if signerOpts != nil {
		hashFuncData, err := json.Marshal(signerOpts.HashFunc())
		if err != nil {
			return nil, err
		}
		signOptions.MessageOption.SignerOpts = &kmsproto.SignerOpts{
			HashFuncData: hashFuncData,
		}
	}

	signMessageRequest := &kmsproto.SignMessageRequest{
		Message: messageBytes,
	}
	if signOptions != nil {
		signMessageRequest.SignOptions = signOptions
	}

	resp, err := c.client.SignMessage(context.Background(), signMessageRequest)
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

func (s *GRPCServer) SignMessage(ctx context.Context, req *kmsproto.SignMessageRequest) (*kmsproto.SignMessageResponse, error) {
	messageReader := bytes.NewReader(req.Message)

	opts := []signature.SignOption{}
	if req.SignOptions != nil {
		signOptions := req.SignOptions

		messageOption := signOptions.MessageOption
		if messageOption != nil {
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
		}
	}
	spew.Dump(opts)

	signature, err := s.Impl.SignMessage(messageReader, opts...)
	if err != nil {
		return nil, err
	}
	return &kmsproto.SignMessageResponse{Signature: signature}, nil
}

func (c *GRPCClient) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	// signatureBytes, err := io.ReadAll(signature)
	// if err != nil {
	// 	return err
	// }
	// messageBytes, err := io.ReadAll(message)
	// if err != nil {
	// 	return err
	// }
	// optsAnies := []*anypb.Any{}
	// for _, opt := range opts {
	// 	any, err := JSONMarshallToAnyPB(&opt)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	optsAnies = append(optsAnies, any)
	// }
	// if _, err = c.client.VerifySignature(context.Background(), &kmsproto.VerifySignatureRequest{
	// 	Signature: signatureBytes,
	// 	Message:   messageBytes,
	// 	Opts:      optsAnies,
	// }); err != nil {
	// 	return err
	// }
	return nil
}

func (s *GRPCServer) VerifySignature(ctx context.Context, req *kmsproto.VerifySignatureRequest) (*kmsproto.VerifySignatureResponse, error) {
	// signatureReader := bytes.NewReader(req.Signature)
	// messageReader := bytes.NewReader(req.Message)
	// opts := []signature.VerifyOption{}
	// for _, any := range req.Opts {
	// 	var opt signature.VerifyOption
	// 	err := JSONUnmarshallFromAnyPB(&opt, any)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	opts = append(opts, opt)
	// }
	// err := s.Impl.VerifySignature(signatureReader, messageReader, opts...)
	// if err != nil {
	// 	return nil, err
	// }
	return &kmsproto.VerifySignatureResponse{}, nil
}

func (c *GRPCClient) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	// optsAnies := []*anypb.Any{}
	// for _, opt := range opts {
	// 	any, err := JSONMarshallToAnyPB(&opt)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	optsAnies = append(optsAnies, any)
	// }
	// resp, err := c.client.PublicKey(context.Background(), &kmsproto.PublicKeyRequest{
	// 	Opts: optsAnies,
	// })
	// if err != nil {
	// 	return nil, err
	// }
	// publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(resp.PublicKey.Value)
	// if err != nil {
	// 	return nil, err
	// }
	// return publicKey, nil
	return nil, nil
}

func (s *GRPCServer) PublicKey(ctx context.Context, req *kmsproto.PublicKeyRequest) (*kmsproto.PublicKeyResponse, error) {
	// opts := []signature.PublicKeyOption{}
	// for _, any := range req.Opts {
	// 	var opt signature.PublicKeyOption
	// 	err := JSONUnmarshallFromAnyPB(&opt, any)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	opts = append(opts, opt)
	// }
	// val, err := s.Impl.PublicKey(opts...)
	// if err != nil {
	// 	return nil, err
	// }
	// any := &anypb.Any{}
	// any.TypeUrl = "type.googleapis.com/google.protobuf.Any"
	// any.Value, err = cryptoutils.MarshalPrivateKeyToPEM(val)
	// if err != nil {
	// 	return nil, err
	// }
	// return &kmsproto.PublicKeyResponse{PublicKey: any}, nil
	return nil, nil
}

// func (c *GRPCClient) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
// 	anyErrFunc, err := JSONMarshallToAnyPB(&errFunc)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	resp, err := c.client.CryptoSigner(context.Background(), &kmsproto.CryptoSignerRequest{
// 		ErrFunc: anyErrFunc,
// 	})
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	signer := crypto.Signer{}
// 	signerOpts := crypto.SignerOpts{}
// 	JSONUnmarshallFromAnyPB(resp.Signer, signer)
// 	return
// }

func encode[T any](t T) ([]byte, error) {
	return json.Marshal(t)
}

func decode[T any](data []byte, t *T) error {
	return json.Unmarshal(data, t)
}

func GobEncode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func GobDecode[S any](data []byte, s *S) error {
	dec := gob.NewDecoder(bytes.NewBuffer(data))
	return dec.Decode(s)
}

func JSONMarshallToAnyPB[V any](v *V) (*anypb.Any, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	anyPB := &anypb.Any{
		TypeUrl: "type.googleapis.com/google.protobuf.Any",
		Value:   bytes,
	}
	return anyPB, nil
}

// func JSONMarshallSlicetoAnyPBs[V any](vSlice []V) ([]anypb.Any, error) {
// 	anySlice := []anypb.Any{}
// 	for _, v := range vSlice {
// 		anyValue, err := JSONMarshallToAnyPB(&v)
// 		if err != nil {
// 			return nil, err
// 		}
// 		anySlice = append(anySlice, *anyValue)
// 	}
// 	return anySlice, nil
// }

func JSONUnmarshallFromAnyPB[S any](s *S, anyPB *anypb.Any) error {
	err := json.Unmarshal(anyPB.Value, s)
	if err != nil {
		return err
	}
	return nil
}

// func JSONUNMarshallSliceFromAnyPBs[S any](s )

// func ConvertInterfaceToAnyPB(v interface{}) (*anypb.Any, error) {
// 	anyValue := &anypb.Any{}
// 	bytes, _ := json.Marshal(v)
// 	bytesValue := &wrapperspb.BytesValue{
// 		Value: bytes,
// 	}
// 	err := anypb.MarshalFrom(anyValue, bytesValue, proto.MarshalOptions{})
// 	return anyValue, err
// }

// func ConvertAnyToInterface(any *anypb.Any) (interface{}, error) {
// 	var value interface{}
// 	bytesValue := &wrapperspb.BytesValue{}
// 	err := anypb.UnmarshalTo(any, bytesValue, proto.UnmarshalOptions{})
// 	if err != nil {
// 		return value, err
// 	}
// 	uErr := json.Unmarshal(bytesValue.Value, &value)
// 	if uErr != nil {
// 		return value, uErr
// 	}
// 	return value, nil
// }

// func ConvertInterfaceSliceToAnySlice(vSlice ...interface{}) ([]*any.Any, error) {
// 	anySlice := []*any.Any{}
// 	for _, v := range vSlice {
// 		anyValue, err := ConvertInterfaceToAny(v)
// 		if err != nil {
// 			return nil, err
// 		}
// 		anySlice = append(anySlice, anyValue)
// 	}
// 	return anySlice, nil
// }
