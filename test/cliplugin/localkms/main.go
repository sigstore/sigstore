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

// Package main implements fake signer to be used in tests
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

const expectedProtocolVersion = "1"

func main() {
	// we log to stderr, not stdout. stdout is reserved for the plugin return value.
	spew.Fdump(os.Stderr, os.Args)
	if protocolVersion := os.Args[1]; protocolVersion != expectedProtocolVersion {
		err := fmt.Errorf("expected protocl version: %s, got %s", expectedProtocolVersion, protocolVersion)
		handler.WriteErrorResponse(os.Stdout, err)
		log.Fatal(err)
	}

	pluginArgs, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	spew.Fdump(os.Stderr, pluginArgs)

	signerVerifier := &LocalSignerVerifier{
		hashFunc:      pluginArgs.InitOptions.HashFunc,
		keyResourceID: pluginArgs.InitOptions.KeyResourceID,
	}

	resp, err := handler.Dispatch(os.Stdout, os.Stdin, pluginArgs, signerVerifier)
	if err != nil {
		log.Fatal(err)
	}
	spew.Fdump(os.Stderr, resp)
}

// don't do this because it's more clean if the host redirects the child's stderr to its own stderr
// defer func() {
// 	if r := recover(); r != nil {
// 		cliplugin.WriteErrorResponse(errors.New(fmt.Sprint(r)))
// 		panic(r)
// 	}
// }()
// panic("my-panic")
