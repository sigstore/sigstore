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
	"encoding/gob"
	"io"

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
	gob.Register(options.RequestContext{})
}

type IOReaderGobWrapper struct {
	Reader io.Reader
}

func (w IOReaderGobWrapper) GobEncode() ([]byte, error) {
	return io.ReadAll(w.Reader)
}

func (w *IOReaderGobWrapper) GobDecode(content []byte) error {
	w.Reader = bytes.NewReader(content)
	return nil
}

func (w IOReaderGobWrapper) Read(p []byte) (int, error) {
	return w.Reader.Read(p)
}
