package cliplugin

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	PluginBinaryName              = "cliplugin"
	SubcommandSupportedAlgorithms = "supported-algorithms"
	SubcommandPublicKey           = "public-key"
	SubcommandSignMessage         = "sign-message"
	ReferenceScheme               = "cliplugin://"
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(ctx context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID, hashFunc)
	})
}

func LoadSignerVerifier(ctx context.Context, keyresourceID string, hashFunc crypto.Hash) (sigkms.SignerVerifier, error) {
	return &CLIKMS{
		ctx: ctx,
		initOptions: InitOptions{
			KeyResourceID: strings.TrimPrefix(keyresourceID, ReferenceScheme),
			HashFunc:      hashFunc,
		},
	}, nil
}

type CLIKMS struct {
	sigkms.SignerVerifier
	ctx         context.Context
	initOptions InitOptions
}

type SupportedAlgorithmsResp struct {
	SupportedAlgorithms []string
}

func invokePlugin(ctx context.Context, resp interface{}, stdin io.Reader, initOptions *InitOptions, subcommand string, args interface{}) error {
	// slog.Info("invokePlugin", "initOptions", initOptions, "subcommand", subcommand, "args", args)
	argsEnc, err := json.Marshal(args)
	if err != nil {
		return err
	}
	initOptionsEnc, err := json.Marshal(initOptions)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, PluginBinaryName, string(initOptionsEnc), subcommand, string(argsEnc))
	cmd.Stdin = stdin

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	// slog.Info("invokePlugin", "start", "starting")
	if err := cmd.Start(); err != nil {
		return err
	}
	// slog.Info("invokePlugin", "start", "started")

	stdout, err := io.ReadAll(stdoutPipe)
	if err != nil {
		return err
	}
	slog.Info("invokePlugin", "readstdout", stdout)
	stderr, err := io.ReadAll(stderrPipe)
	if err != nil {
		return err
	}
	slog.Info("invokePlugin", "readstderr", stderr)
	if err = cmd.Wait(); err != nil {
		return err
	}
	fmt.Print(string(stderr))

	err = json.Unmarshal(stdout, resp)
	slog.Info("invokePlugin", "unmarshall", resp)
	return err
}

func (c CLIKMS) SupportedAlgorithms() (result []string) {
	var args interface{}
	var resp SupportedAlgorithmsResp
	if err := invokePlugin(context.TODO(), &resp, nil, &c.initOptions, SubcommandPublicKey, args); err != nil {
		log.Fatal(err)
	}
	return resp.SupportedAlgorithms
}

type PublicKeyArgs struct {
	KeyVersion string
}

type PublicKeyResp struct {
	PublicKeyPEM []byte
}

func (c CLIKMS) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.TODO()
	keyVersion := "1"
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyKeyVersion(&keyVersion)
	}
	args := &PublicKeyArgs{
		KeyVersion: keyVersion,
	}
	var resp PublicKeyResp
	if err := invokePlugin(ctx, &resp, nil, &c.initOptions, SubcommandPublicKey, args); err != nil {
		return nil, err
	}
	// slog.Info("PublicKey", "pem", resp.PublicKeyPEM)
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(resp.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

type SignMessageArgs struct {
	HashFunc   crypto.Hash
	KeyVersion string
}

type SignMessageResp struct {
	Signature []byte
}

func (c CLIKMS) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	ctx := c.ctx
	var signerOpts crypto.SignerOpts = c.initOptions.HashFunc
	var keyVersion string
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyCryptoSignerOpts(&signerOpts)
		opt.ApplyKeyVersion(&keyVersion)
	}
	args := SignMessageArgs{
		HashFunc:   signerOpts.HashFunc(),
		KeyVersion: keyVersion,
	}
	var resp SignMessageResp

	// if b, err := io.ReadAll(message); err != nil {
	// 	return nil, err
	// } else {
	// 	slog.Info("SignMessage", "message", b)
	// }
	subCommand := SubcommandSignMessage
	if err := invokePlugin(ctx, &resp, message, &c.initOptions, subCommand, args); err != nil {
		return nil, err
	}
	signature := resp.Signature
	return signature, nil
}

func writeResponse(resp interface{}) error {
	enc, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, string(enc))
	return nil
}

type InitOptions struct {
	KeyResourceID string
	KeyVersion    string
	HashFunc      crypto.Hash
}

func GetInitOptions() (*InitOptions, error) {
	args := os.Args
	initOptionsJSON := args[1]
	var initOptions InitOptions
	if err := json.Unmarshal([]byte(initOptionsJSON), &initOptions); err != nil {
		return nil, err
	}
	return &initOptions, nil
}

func HandleSubcommand(impl sigkms.SignerVerifier) error {
	if err := func() error {
		args := os.Args
		// slog.Error("plugin", "args", args)
		subCommand := args[2]
		subCommandArgs := args[3]
		switch subCommand {
		case SubcommandSupportedAlgorithms:
			supportedAlgorithms := impl.SupportedAlgorithms()
			resp := &SupportedAlgorithmsResp{
				SupportedAlgorithms: supportedAlgorithms,
			}
			if err := writeResponse(resp); err != nil {
				return err
			}
		case SubcommandPublicKey:
			var publicKeyArgs PublicKeyArgs
			if err := json.Unmarshal([]byte(subCommandArgs), &publicKeyArgs); err != nil {
				return err
			}
			opts := []signature.PublicKeyOption{
				options.WithKeyVersion(publicKeyArgs.KeyVersion),
			}
			// slog.Error("HandlePluginInvocation", "subcommand", subCommand, "opts", opts, "impl", impl)
			publicKey, err := impl.PublicKey(opts...)
			if err != nil {
				return err
			}
			publicKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
			if err != nil {
				return err
			}
			// slog.Error("HandlePluginInvocation", "subcommand", subCommand, "pem", publicKeyPEM)
			resp := &PublicKeyResp{
				PublicKeyPEM: publicKeyPEM,
			}
			if err := writeResponse(resp); err != nil {
				return err
			}
		case SubcommandSignMessage:
			var signMessageArgs SignMessageArgs
			if err := json.Unmarshal([]byte(subCommandArgs), &signMessageArgs); err != nil {
				return err
			}
			opts := []signature.SignOption{
				options.WithKeyVersion(signMessageArgs.KeyVersion),
				options.WithCryptoSignerOpts(signMessageArgs.HashFunc),
			}
			message := os.Stdin
			signature, err := impl.SignMessage(message, opts...)
			if err != nil {
				return err
			}
			resp := &SignMessageResp{
				Signature: signature,
			}
			if err := writeResponse(resp); err != nil {
				return err
			}
		default:
			return fmt.Errorf("uknown arg: %s", subCommand)
		}
		return nil
	}(); err != nil {

		slog.Error(err.Error())
	}
	return nil
}
