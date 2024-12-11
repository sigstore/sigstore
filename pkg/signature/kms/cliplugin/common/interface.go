package common

import (
	"crypto"
	"time"

	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	ProtocolVersion               = "1"
	DefaultAlgorithmMethodName    = "defaultAlgorithm"
	SupportedAlgorithmsMethodName = "supportedAlgorithms"
	PublicKeyMethodName           = "publicKey"
	CreateKeyMethodName           = "createKey"
	SignMessageMethodName         = "signMessage"
	VerifySignatureMethodName     = "verifySignature"
)

type InitOptions struct {
	ProtocolVersion string      `json:"protocolVersion"`
	KeyResourceID   string      `json:"keyResourceID"`
	HashFunc        crypto.Hash `json:"hashFunc"`
	// RPCOptions comes from the initial opts in cliplugin's LoadSignerVerifier().
	// This will not be directly used to override unsupplied opts in PluginClient's methods,
	// nor will the RPCOptions.CtxDeadline be used within Command objects.
	// Instead, plugin authors may use it for KMS-specific initialization tasks.
	*RPCOptions
}

type PluginArgs struct {
	*MethodArgs
	InitOptions *InitOptions `json:"initOptions"`
}

type MethodArgs struct {
	MethodName          string                   `json:"methodName"`
	DefaultAlgorithm    *DefaultAlgorithmArgs    `json:"defaultAlgorithm,omitempty"`
	SupportedAlgorithms *SupportedAlgorithmsArgs `json:"suportedAlgorithms,omitempty"`
	PublicKey           *PublicKeyArgs           `json:"publicKey,omitempty"`
	CreateKey           *CreateKeyArgs           `json:"createKey,omitempty"`
	SignMessage         *SignMessageArgs         `json:"signMessage,omitempty"`
	VerifySignature     *VerifySignatureArgs     `json:"verifySignature,omitempty"`
}

type PluginResp struct {
	ErrorMessage        string                   `json:"errorMessage,omitempty"`
	DefaultAlgorithm    *DefaultAlgorithmResp    `json:"defaultAlgorithm,omitempty"`
	SupportedAlgorithms *SupportedAlgorithmsResp `json:"supportedAlgorithms,omitempty"`
	PublicKey           *PublicKeyResp           `json:"publicKey,omitempty"`
	CreateKey           *CreateKeyResp           `json:"createKey,omitempty"`
	SignMessage         *SignMessageResp         `json:"signMessage,omitempty"`
	VerifySignature     *VerifySignatureResp     `json:"verifySignature,omitempty"`
}

type DefaultAlgorithmArgs struct {
}

type DefaultAlgorithmResp struct {
	DefaultAlgorithm string
}

type SupportedAlgorithmsArgs struct {
}

type SupportedAlgorithmsResp struct {
	SupportedAlgorithms []string
}

type PublicKeyArgs struct {
	PublicKeyOptions *PublicKeyOptions `json:"publicKeyOptions"`
}

type PublicKeyOptions struct {
	*RPCOptions
}

type PublicKeyResp struct {
	PublicKeyPEM []byte
}

type CreateKeyArgs struct {
	CtxDeadline *time.Time
	Algorithm   string
}

type CreateKeyResp struct {
	PublicKeyPEM []byte
}

type SignMessageArgs struct {
	SignOptions *SignOptions `json:"signOptions"`
}

type SignOptions struct {
	*RPCOptions
	*MessageOptions
}

type RPCOptions struct {
	CtxDeadline        *time.Time       `json:"ctxDeadline,omitempty"`
	KeyVersion         *string          `json:"keyVersion,omitempty"`
	RPCAuth            *options.RPCAuth `json:"rpcAuth,omitempty"` // fully JSON-serializable
	RemoteVerification *bool            `json:"remoteVerification,omitempty"`
}

type MessageOptions struct {
	Digest   *[]byte      `json:"digest,omitempty"`
	HashFunc *crypto.Hash `json:"hashFunc,omitempty"`
}

type SignMessageResp struct {
	Signature []byte `json:"signature"`
}

type VerifySignatureArgs struct {
	Signature     *[]byte        `json:"signature"`
	VerifyOptions *VerifyOptions `json:"verifyOptions"`
}

type VerifyOptions struct {
	*RPCOptions
	*MessageOptions
}

type VerifySignatureResp struct {
}
