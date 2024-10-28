package common

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-plugin"
)

var (
	testDeadLine  = time.Now().Add(5 * time.Minute)
	testAlgorithm = "test-algorithm"
	testPublicKey crypto.PublicKey
)

type TestSignerVerifierImpl struct {
	KMSGoPluginSignerVerifier
}

func (TestSignerVerifierImpl) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	slog.Info("impl", "ctx", ctx, "algorithm", algorithm)
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

func Test_Connection(t *testing.T) {
	// prepare testPublicKey
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	// slog.Info("priv", "priv", priv)
	testPublicKey = priv.Public()

	ctx, cancel := context.WithCancel(context.Background())

	// server and channels to receive the reattach config.
	reattachConfigCh := make(chan *plugin.ReattachConfig, 1)
	closeCh := make(chan struct{})
	go plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			KMSPluginName: &SignerVerifierRPCPlugin{Impl: TestSignerVerifierImpl{}},
		},
		Test: &plugin.ServeTestConfig{
			Context:          ctx,
			ReattachConfigCh: reattachConfigCh,
			CloseCh:          closeCh,
		},
	})

	var reattachConfig *plugin.ReattachConfig
	reattachConfig = <-reattachConfigCh

	// connect.
	client := plugin.NewClient(&plugin.ClientConfig{
		Cmd:             nil,
		HandshakeConfig: HandshakeConfig,
		Plugins:         PluginMap,
		Reattach:        reattachConfig,
	})

	// exttact the interface.
	rpcClient, err := client.Client()
	if err != nil {
		t.Fatalf("could not get client: %v", err)
	}
	raw, err := rpcClient.Dispense(KMSPluginName)
	if err != nil {
		t.Fatalf("ould not dispense: %v", err)
	}
	signerVerifier := raw.(*SignerVerifierRPC)
	slog.Info("sv", "val", signerVerifier)

	// test the interface.
	wantedPublicKey := testPublicKey
	ctx, _ = context.WithDeadline(ctx, testDeadLine)
	gotPublicKey, err := signerVerifier.CreateKey(ctx, testAlgorithm)
	if err != nil {
		t.Fatalf("could not get public key: %v", err)
	}
	if diff := cmp.Diff(wantedPublicKey, gotPublicKey); diff != "" {
		t.Errorf("PublicKey mismatch (-want +got):\n%s", diff)
	}
	slog.Info("done", "sv", signerVerifier)
	client.Kill()
	cancel()
	<-closeCh
}

// func TestServer_testMode_AutoMTLS(t *testing.T) {
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	closeCh := make(chan struct{})
// 	go Serve(&ServeConfig{
// 		HandshakeConfig: testVersionedHandshake,
// 		VersionedPlugins: map[int]PluginSet{
// 			2: testGRPCPluginMap,
// 		},
// 		GRPCServer: DefaultGRPCServer,
// 		Logger:     hclog.NewNullLogger(),
// 		Test: &ServeTestConfig{
// 			Context:          ctx,
// 			ReattachConfigCh: nil,
// 			CloseCh:          closeCh,
// 		},
// 	})

// 	// Connect!
// 	process := helperProcess("test-mtls")
// 	c := NewClient(&ClientConfig{
// 		Cmd:             process,
// 		HandshakeConfig: testVersionedHandshake,
// 		VersionedPlugins: map[int]PluginSet{
// 			2: testGRPCPluginMap,
// 		},
// 		AllowedProtocols: []Protocol{ProtocolGRPC},
// 		AutoMTLS:         true,
// 	})
// 	client, err := c.Client()
// 	if err != nil {
// 		t.Fatalf("err: %s", err)
// 	}

// 	// Pinging should work
// 	if err := client.Ping(); err != nil {
// 		t.Fatalf("should not err: %s", err)
// 	}

// 	// Grab the impl
// 	raw, err := client.Dispense("test")
// 	if err != nil {
// 		t.Fatalf("err should be nil, got %s", err)
// 	}

// 	tester, ok := raw.(testInterface)
// 	if !ok {
// 		t.Fatalf("bad: %#v", raw)
// 	}

// 	n := tester.Double(3)
// 	if n != 6 {
// 		t.Fatal("invalid response", n)
// 	}

// 	// ensure we can make use of bidirectional communication with AutoMTLS
// 	// enabled
// 	err = tester.Bidirectional()
// 	if err != nil {
// 		t.Fatal("invalid response", err)
// 	}

// 	c.Kill()
// 	// Canceling should cause an exit
// 	cancel()
// 	<-closeCh
// }
