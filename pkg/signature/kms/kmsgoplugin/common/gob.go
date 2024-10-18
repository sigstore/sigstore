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
	"io"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// gob encode/decode utilities.

func init() {
	GobRegister()
}

// GobRegister will call gob.Register on a few known structs:
// IOReaderGobWrapper{}
// options.RequestContext{}
// The privaete ctx of options.RequestContext will not be faithfully encoded/decoded.
// See https://github.com/golang/go/issues/22290.
func GobRegister() {
	gob.Register(IOReaderGobWrapper{})
	// TODO: why dont i need to register this?
	gob.Register(PublicKeyGobWrapper{})
	// gob.Register(CryptoSignerGobWrapper{})
	gob.Register(options.RequestContext{})
	gob.Register(options.RequestDigest{})
	gob.Register(options.RequestHash{})
}

// GobEncoderDecoder is a helper container for both of the gob encoding and decoding methods.
type GobEncoderDecoder interface {
	gob.GobEncoder
	gob.GobDecoder
}

type IOReaderGobWrapper struct {
	io.Reader
}

func (r IOReaderGobWrapper) GobEncode() ([]byte, error) {
	return io.ReadAll(r.Reader)
}

func (r *IOReaderGobWrapper) GobDecode(content []byte) error {
	r.Reader = bytes.NewReader(content)
	return nil
}

type PublicKeyGobWrapper struct {
	GobEncoderDecoder
	crypto.PublicKey
	PublicKeyData []byte
}

func (p PublicKeyGobWrapper) GobEncode() ([]byte, error) {
	return cryptoutils.MarshalPublicKeyToPEM(p.PublicKey)
}

func (p *PublicKeyGobWrapper) GobDecode(content []byte) error {
	var err error
	p.PublicKey, err = cryptoutils.UnmarshalPEMToPublicKey(content)
	return err
}

type SignOptionsSlice []signature.SignOption

type SignOptionGobWrapper struct {
	SignOptionsSlice
}

func (s SignOptionGobWrapper) GobEncode() ([]byte, error) {
	var digestBytes []byte
	var signerOpts crypto.SignerOpts
	for _, opt := range s.SignOptionsSlice {
		opt.ApplyDigest(&digestBytes)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}
	if signerOpts != nil {
		s.SignOptionsSlice = append(s.SignOptionsSlice, options.WithHash(signerOpts.HashFunc()))
	}
	return json.Marshal(s.SignOptionsSlice)
}

func (s *SignOptionGobWrapper) GobDecode(content []byte) error {
	return json.Unmarshal(content, &s.SignOptionsSlice)
}

// type
