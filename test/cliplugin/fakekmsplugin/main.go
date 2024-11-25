package main

import (
	"context"
	"crypto"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin"
	"github.com/sigstore/sigstore/pkg/signature/kms/fake"
	"github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common"
)

const expectedProtocolVersion = "11"

func main() {
	slog.Info("plugin", "args", os.Args[1])
	if protocolVersion := os.Args[1]; protocolVersion != expectedProtocolVersion {
		err := fmt.Errorf("expected protocl version: %s, got %s", expectedProtocolVersion, protocolVersion)
		cliplugin.WriteErrorResponse(err)
		log.Fatal(err)
	}
	pluginArgs, err := cliplugin.GetPluginArgs(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	initOptions := pluginArgs.InitOptions
	slog.Info("plugin", "args", pluginArgs)
	var sv kms.SignerVerifier
	sv, err = fake.LoadSignerVerifier(context.TODO(), crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}
	sv = &LocalSignerVerifier{
		state: &common.KMSGoPluginState{
			HashFunc:      initOptions.HashFunc,
			KeyResourceID: initOptions.KeyResourceID,
		},
	}
	resp, err := cliplugin.Dispatch(os.Stdin, pluginArgs, sv)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	slog.Info("plugin", "resp", resp, "err", err)
}

// slog.Error("plugin", "args", os.Args)

// don't do this because it's more clean if the host redirects the child's stderr to its own stderr
// defer func() {
// 	if r := recover(); r != nil {
// 		cliplugin.WriteErrorResponse(errors.New(fmt.Sprint(r)))
// 		panic(r)
// 	}
// }()
// panic("my-panic")
