package common

import (
	"crypto"
	"time"
)

const (
	ProtocolVersion               = "1"
	DefaultAlgorithmMethodName    = "defaultAlgorithm"
	SupportedAlgorithmsMethodName = "supportedAlgorithms"
	PublicKeyMethodName           = "publicKey"
	CreateKeyMethodName           = "createKey"
	SignMessageMethodName         = "signMessage"
)

type InitOptions struct {
	ProtocolVersion string      `json:"protocolVersion"`
	KeyResourceID   string      `json:"keyResourceID"`
	KeyVersion      string      `json:"keyVersion,omitempty"`
	HashFunc        crypto.Hash `json:"hashFunc"`
	CtxDeadline     *time.Time  `json:"timeout,omitempty"`
}

type PluginArgs struct {
	Method             string                   `json:"method"`
	DefaultAlgorithm   *DefaultAlgorithmArgs    `json:"defaultAlgorithm,omitempty"`
	SuportedAlgorithms *SupportedAlgorithmsArgs `json:"suportedAlgorithms,omitempty"`
	PublicKey          *PublicKeyArgs           `json:"publicKey,omitempty"`
	CreateKey          *CreateKeyArgs           `json:"createKey,omitempty"`
	SignMessage        *SignMessageArgs         `json:"signMessage,omitempty"`
	InitOptions        *InitOptions             `json:"initOptions"`
}

type PluginResp struct {
	ErrorMessage        string                   `json:"errorMessage,omitempty"`
	DefaultAlgorithm    *DefaultAlgorithmResp    `json:"defaultAlgorithm,omitempty"`
	SupportedAlgorithms *SupportedAlgorithmsResp `json:"supportedAlgorithms,omitempty"`
	PublicKey           *PublicKeyResp           `json:"publicKey,omitempty"`
	CreateKey           *CreateKeyResp           `json:"createKey,omitempty"`
	SignMessage         *SignMessageResp         `json:"signMessage,omitempty"`
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
	KeyVersion string
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
	HashFunc   crypto.Hash `json:"hashFunc"`
	KeyVersion string      `json:"keyVersion"`
}

type SignMessageResp struct {
	Signature []byte `json:"signature"`
}
