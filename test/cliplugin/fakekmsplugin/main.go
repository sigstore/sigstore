package main

import (
	"context"
	"crypto"
	"log"
	"log/slog"
	"os"

	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin"
	"github.com/sigstore/sigstore/pkg/signature/kms/fake"
	"github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common"
)

// type SignerVerifier struct {
// 	signature.SignerVerifier
// }

// func (s SignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
// 	return nil, nil
// }

// func (s SignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
// 	return nil, nil
// }

func main() {
	slog.Error("plugin", "args", os.Args)
	initOptions, err := cliplugin.GetInitOptions()
	if err != nil {
		// slog.Error(err.Error())
		log.Fatal(err)
	}
	slog.Info("plugin", "initoptions", initOptions)
	var sv kms.SignerVerifier
	sv, err = fake.LoadSignerVerifier(context.TODO(), crypto.SHA256)
	if err != nil {
		// slog.Error(err.Error())
		log.Fatal(err)
	}
	sv = &LocalSignerVerifier{
		state: &common.KMSGoPluginState{
			HashFunc:      initOptions.HashFunc,
			KeyResourceID: initOptions.KeyResourceID,
		},
	}
	if err := cliplugin.HandleSubcommand(sv); err != nil {
		slog.Error(err.Error())
	}
}
