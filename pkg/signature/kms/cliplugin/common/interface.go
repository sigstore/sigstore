package common

import (
	"crypto"
)

const (
	ProtocolVersion               = "1"
	SupportedAlgorithmsMethodName = "supportedAlgorithms"
	SignMessageMethodName         = "signMessage"
	// TODO: Additonal methods to be implemented
)

type PluginArgs struct {
	*MethodArgs
	InitOptions *InitOptions `json:"initOptions"`
}

type InitOptions struct {
	ProtocolVersion string      `json:"protocolVersion"`
	KeyResourceID   string      `json:"keyResourceID"`
	HashFunc        crypto.Hash `json:"hashFunc"`
	// TODO: extracted values from signature.RPCOption from LoadSignerVerifier().
}

type MethodArgs struct {
	MethodName          string                   `json:"methodName"`
	SupportedAlgorithms *SupportedAlgorithmsArgs `json:"supportedAlgorithms,omitempty"`
	SignMessage         *SignMessageArgs         `json:"signMessage,omitempty"`
	// TODO: Additonal methods to be implemented
}

type PluginResp struct {
	ErrorMessage        string                   `json:"errorMessage,omitempty"`
	SupportedAlgorithms *SupportedAlgorithmsResp `json:"supportedAlgorithms,omitempty"`
	SignMessage         *SignMessageResp         `json:"signMessage,omitempty"`
	// TODO: Additonal methods to be implemented
}

type SupportedAlgorithmsArgs struct {
}

type SupportedAlgorithmsResp struct {
	SupportedAlgorithms []string
}

type SignMessageArgs struct {
	// TODO: use extracted values from signature.RPCOption, and signature.SignOption.
}

type SignMessageResp struct {
	Signature []byte `json:"signature"`
}
