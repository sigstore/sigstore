package cliplugin

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

const (
	pluginBinaryPrefix = "sigstore-kms-"
)

func init() {
	kms.AddProvider(kms.CLIPluginProviderKey, func(ctx context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (kms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID, hashFunc, opts...)
	})
}

func LoadSignerVerifier(ctx context.Context, inputKeyresourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (kms.SignerVerifier, error) {
	parts := strings.SplitN(inputKeyresourceID, "://", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: expected format: [plugin name]://[key ref], got: %s", ErrorParsingPluginName, inputKeyresourceID)
	}
	pluginName, keyResourceID := parts[0], parts[1]
	executable := pluginBinaryPrefix + pluginName
	initOptions := &common.InitOptions{
		ProtocolVersion: common.ProtocolVersion,
		KeyResourceID:   keyResourceID,
		HashFunc:        hashFunc,
		// TODO: include extracted values from opts
	}
	pluginClient := newPluginClient(executable, initOptions, makeCommand)
	return pluginClient, nil
}
