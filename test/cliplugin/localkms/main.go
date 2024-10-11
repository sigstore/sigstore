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
	if protocolVersion := os.Args[1]; protocolVersion != expectedProtocolVersion {
		err := fmt.Errorf("expected protocl version: %s, got %s", expectedProtocolVersion, protocolVersion)
		handler.WriteErrorResponse(os.Stdout, err)
		log.Fatal(err)
	}

	pluginArgs, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		log.Fatal(err)
	}

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