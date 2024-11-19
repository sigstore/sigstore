package common

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-plugin"
)

var (
	testDeadLine                  = time.Now().Add(5 * time.Minute)
	testAlgorithm                 = "test-algorithm"
	testPublicKey                 crypto.PublicKey
	testKMSGoPluginSignerVerifier *SignerVerifierRPC
	testCtx                       context.Context
)

type TestSignerVerifierImpl struct {
	KMSGoPluginSignerVerifier
}

func (TestSignerVerifierImpl) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, fmt.Errorf("expected a deadline")
	}
	if diff := cmp.Diff(deadline, testDeadLine); diff != "" {
		fmt.Errorf("Deadline not equal (-want +got):\n%s", diff)
	}
	if algorithm != testAlgorithm {
		return nil, fmt.Errorf("unexpected algorithm: %s", algorithm)
	}
	return testPublicKey, nil
}

func TestMain(m *testing.M) {
	// Perform global setup here

	// prepare testPublicKey
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("rsa.GenerateKey failed: %v", err))
	}
	testPublicKey = priv.Public()

	// prepare the server and client
	// server and channels to receive the reattach config.
	ctx, cancel := context.WithCancel(context.Background())
	testCtx = ctx
	reattachConfigCh := make(chan *plugin.ReattachConfig, 1)
	closeCh := make(chan struct{})
	go plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			KMSPluginNameRPC: &SignerVerifierRPCPlugin{Impl: TestSignerVerifierImpl{}},
		},
		Test: &plugin.ServeTestConfig{
			Context:          ctx,
			ReattachConfigCh: reattachConfigCh,
			CloseCh:          closeCh,
		},
	})
	var reattachConfig *plugin.ReattachConfig
	reattachConfig = <-reattachConfigCh
	client := plugin.NewClient(&plugin.ClientConfig{
		Cmd:             nil,
		HandshakeConfig: HandshakeConfig,
		Plugins:         RPCPluginMap,
		Reattach:        reattachConfig,
	})
	rpcClient, err := client.Client()
	if err != nil {
		panic(fmt.Sprintf("could not get client: %v", err))
	}
	raw, err := rpcClient.Dispense(KMSPluginNameRPC)
	if err != nil {
		panic(fmt.Sprintf("ould not dispense: %v", err))
	}
	testKMSGoPluginSignerVerifier = raw.(*SignerVerifierRPC)

	exitCode := m.Run() // Run all tests

	client.Kill()
	cancel()
	<-closeCh

	// Perform global teardown here

	os.Exit(exitCode)
}

func Test_CreateKey(t *testing.T) {
	ctx := testCtx
	signerVerifier := testKMSGoPluginSignerVerifier
	wantedPublicKey := testPublicKey
	ctx, cancel := context.WithDeadline(ctx, testDeadLine)
	gotPublicKey, err := signerVerifier.CreateKey(ctx, testAlgorithm)
	if err != nil {
		t.Fatalf("could not get public key: %v", err)
	}
	if diff := cmp.Diff(wantedPublicKey, gotPublicKey); diff != "" {
		t.Errorf("PublicKey mismatch (-want +got):\n%s", diff)
	}
	cancel()
}

func Test_CreateKey2(t *testing.T) {
	ctx := testCtx
	signerVerifier := testKMSGoPluginSignerVerifier
	wantedPublicKey := testPublicKey
	ctx, cancel := context.WithDeadline(ctx, testDeadLine)
	gotPublicKey, err := signerVerifier.CreateKey(ctx, testAlgorithm)
	if err != nil {
		t.Fatalf("could not get public key: %v", err)
	}
	if diff := cmp.Diff(wantedPublicKey, gotPublicKey); diff != "" {
		t.Errorf("PublicKey mismatch (-want +got):\n%s", diff)
	}
	cancel()
}
