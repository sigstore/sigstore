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

// import (
// 	"crypto"
// 	"encoding/json"
// 	"fmt"
// 	"io"

// 	"github.com/golang/protobuf/ptypes/any"
// 	"github.com/golang/protobuf/ptypes/wrappers"
// 	"github.com/sigstore/sigstore/pkg/signature"
// 	kmsproto "github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common/proto"
// 	"google.golang.org/protobuf/proto"
// 	"google.golang.org/protobuf/types/known/anypb"

// 	"context"
// )

// // implementations for the grpc client and server.

// func (c *GRPCClient) SupportedAlgorithms() []string {
// 	resp, err := c.client.SupportedAlgorithms(context.Background(), &kmsproto.SupportedAlgorithmsRequest{})
// 	if err != nil {
// 		panic(fmt.Errorf("%w: %w", ErrorUnreturnableKMSGRPC, err))
// 	}
// 	return resp.SupportedAlgorithms
// }

// func (s *GRPCServer) SupportedAlgorithms(ctx context.Context, req *kmsproto.SupportedAlgorithmsRequest) (*kmsproto.SupportedAlgorithmsResponse, error) {
// 	val := s.Impl.SupportedAlgorithms()
// 	return &kmsproto.SupportedAlgorithmsResponse{SupportedAlgorithms: val}, nil
// }

// func (c *GRPCClient) DefaultAlgorithm() string {
// 	resp, err := c.client.DefaultAlgorithm(context.Background(), &kmsproto.DefaultAlgorithmRequest{})
// 	if err != nil {
// 		panic(fmt.Errorf("%w: %w", ErrorUnreturnableKMSGRPC, err))
// 	}
// 	return resp.DefaultAgorithm
// }

// func (s *GRPCServer) DefaultAlgorithm(ctx context.Context, req *kmsproto.DefaultAlgorithmRequest) (*kmsproto.DefaultAlgorithmResponse, error) {
// 	val := s.Impl.DefaultAlgorithm()
// 	return &kmsproto.DefaultAlgorithmResponse{DefaultAgorithm: val}, nil
// }

// func (c *GRPCClient) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
// 	resp, err := c.client.CreateKey(ctx, &kmsproto.CreateKeyRequest{
// 		Algorithm: algorithm,
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return resp.PublicKey, err
// }

// func (s *GRPCServer) CreateKey(ctx context.Context, req *kmsproto.CreateKeyRequest) (*kmsproto.CreateKeyResponse, error) {
// 	val, err := s.Impl.CreateKey(ctx, req.Algorithm)
// 	if err != nil {
// 		return nil, err
// 	}
//     anyVal, err := anypb.New()
// 	// anyVal := &any.Any{}
// 	// bytes, err := json.Marshal(val)
// 	// if err != nil {
// 	// 	return nil, err
// 	// }
// 	// bytesValue := &wrappers.BytesValue{
// 	// 	Value: bytes,
// 	// }
// 	// if err := anypb.MarshalFrom(anyVal, bytesValue, proto.MarshalOptions{}); err != nil {
// 	// 	return nil, err
// 	// }
// 	return &kmsproto.CreateKeyResponse{PublicKey: anyVal}, nil
// }

// func (c *GRPCClient) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
// 	messageBytes, err := io.ReadAll(message)
// 	if err != nil {
// 		return nil, err
// 	}
// 	optsInterface := make([]interface{}, len(opts))
// 	for i, opt := range opts {
// 		optsInterface[i] = opt
// 	}
// 	optsAny, err := ConvertInterfaceSliceToAnySlice(optsInterface...)
// 	if err != nil {
// 		return nil, err
// 	}
// 	resp, err := c.client.SignMessage(context.Background(), &kmsproto.SignMessageRequest{
// 		Message: messageBytes,
// 		Opts:    optsAny,
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return resp.Signature, err
// }

// func ConvertInterfaceToAny(v interface{}) (*any.Any, error) {
// 	anyValue := &any.Any{}
// 	bytes, _ := json.Marshal(v)
// 	bytesValue := &wrappers.BytesValue{
// 		Value: bytes,
// 	}
// 	err := anypb.MarshalFrom(anyValue, bytesValue, proto.MarshalOptions{})
// 	return anyValue, err
// }

// func ConvertAnyToInterface(anyValue *any.Any) (interface{}, error) {
// 	var value interface{}
// 	bytesValue := &wrappers.BytesValue{}
// 	err := anypb.UnmarshalTo(anyValue, bytesValue, proto.UnmarshalOptions{})
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
