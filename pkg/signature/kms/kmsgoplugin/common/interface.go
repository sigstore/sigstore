package common

import (
	"net/rpc"

	"github.com/sigstore/sigstore/pkg/signature/kms"

	"github.com/hashicorp/go-plugin"
)

// Some of our interface functions don't return an error, but our communication to the plugin may still error,
// so we panic instead of returning the error.

var (
	// HandshakeConfig is the configuration for a proper handshake between client and server of the plugin.
	// This is not authentication, but identification.
	HandshakeConfig = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "SIGSTORE_KMS_PLUGIN",
		MagicCookieValue: "sigstore",
	}
)

// SignerVerifier creates and verifies digital signatures over a message using an in-memory signer
type SignerVerifier struct {
	kms.SignerVerifier
}

type SignerVerifierRPC struct {
	client *rpc.Client
}

type SignerVerifierPlugin struct {
	Impl kms.SignerVerifier
}

func (p *SignerVerifierPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &SignerVerifierPlugin{Impl: p.Impl}, nil
}

func (SignerVerifierPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &SignerVerifierRPC{client: c}, nil
}

// SupportedAlgorithmsArgs contains the args for SupportedAlgorithms().
type SupportedAlgorithmsArgs struct {
}

// SupportedAlgorithmsResp contains the return values for SuuportedAlgorithms().
type SupportedAlgorithmsResp struct {
	SupportedAlgorithms []string
}

// SupportedAlgorithms retrieves a list of supported algorithms.
func (s *SignerVerifierPlugin) SupportedAlgorithms(_ *SupportedAlgorithmsArgs, resp *SupportedAlgorithmsResp) {
	supportedAlgorithms := s.Impl.SupportedAlgorithms()
	*resp = SupportedAlgorithmsResp{
		SupportedAlgorithms: supportedAlgorithms,
	}
}

// SupportedAlgorithms returns a list of supported algorithms.
func (g *SignerVerifierRPC) SupportedAlgorithms() []string {
	args := SupportedAlgorithmsArgs{}
	var resp SupportedAlgorithmsResp
	if err := g.client.Call("Plugin.SupportedAlgorithms", &args, &resp); err != nil {
		panic(err)
	}
	supportedAlgorithmsArgs := resp.SupportedAlgorithms
	return supportedAlgorithmsArgs
}

// DefaultAlgorithmArgs contains the args for DefaultAlgorithm().
type DefaultAlgorithmArgs struct {
}

// DefaultAlgorithmResp contains the return values for SuuportedAlgorithms().
type DefaultAlgorithmResp struct {
	DefaultAlgorithm string
}

// DefaultAlgorithm returns the default algorithm for the signer
func (s *SignerVerifierPlugin) DefaultAlgorithm(_ *DefaultAlgorithmArgs, resp *DefaultAlgorithmResp) {
	defaultAlgorithm := s.Impl.DefaultAlgorithm()
	*resp = DefaultAlgorithmResp{
		DefaultAlgorithm: defaultAlgorithm,
	}
}

// SupportedAlgorithms returns a list of supported algorithms.
func (g *SignerVerifierRPC) DefaultAlgorithm() string {
	args := DefaultAlgorithmArgs{}
	var resp DefaultAlgorithmResp
	if err := g.client.Call("Plugin.DeafultAlgorithm", &args, &resp); err != nil {
		panic(err)
	}
	defaultAlgorithm := resp.DefaultAlgorithm
	return defaultAlgorithm
}
