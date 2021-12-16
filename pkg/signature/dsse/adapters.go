package dsse

import (
	"bytes"
	"crypto"
	"errors"

	"github.com/sigstore/sigstore/pkg/signature"
)

// VerifierAdapter wraps a `sigstore/signature.Verifier`, making it compatible with `go-securesystemslib/dsse.Verifier`.
type SignerAdapter struct {
	SignatureSigner signature.Signer
	Pub             crypto.PublicKey
	Opts            []signature.SignOption
	PubKeyID        string
}

// Sign implements `go-securesystemslib/dsse.Signer`
func (a *SignerAdapter) Sign(data []byte) ([]byte, error) {
	return a.SignatureSigner.SignMessage(bytes.NewReader(data), a.Opts...)
}

// Verify disabled `go-securesystemslib/dsse.Verifier`
func (a *SignerAdapter) Verify(data []byte, sig []byte) error {
	return errors.New("Verify disabled")
}

// Public implements `go-securesystemslib/dsse.Verifier`
func (a *SignerAdapter) Public() crypto.PublicKey {
	return a.Pub
}

// KeyID implements `go-securesystemslib/dsse.Verifier`
func (a SignerAdapter) KeyID() (string, error) {
	return a.PubKeyID, nil
}

// VerifierAdapter wraps a `sigstore/signature.Verifier`, making it compatible with `go-securesystemslib/dsse.Verifier`.
type VerifierAdapter struct {
	SignatureVerifier signature.Verifier
	Pub               crypto.PublicKey
	PubKeyID          string
}

// Verify implements `go-securesystemslib/dsse.Verifier`
func (a *VerifierAdapter) Verify(data []byte, sig []byte) error {
	return a.SignatureVerifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
}

// Public implements `go-securesystemslib/dsse.Verifier`
func (a *VerifierAdapter) Public() crypto.PublicKey {
	return a.Pub
}

// KeyID implements `go-securesystemslib/dsse.Verifier`
func (a *VerifierAdapter) KeyID() (string, error) {
	return a.PubKeyID, nil
}
