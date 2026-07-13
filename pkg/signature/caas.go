package signature

import (
	"context"
	gocrypto "crypto"
	"encoding/binary"
	"errors"
	"io"

	"github.ibm.com/citius/go-sdk/client/crypto"
	"github.ibm.com/citius/go-sdk/client/keymanagement"
	"github.ibm.com/citius/go-sdk/gen/go/api/messages"
	"google.golang.org/protobuf/proto"
)

// LoadCaaSSignerVerifier returns a signature.SignerVerifier for CaaS
func LoadCaaSSignerVerifier(ctx context.Context, sk *CaaSPrivateKey, cryptoClient *crypto.Client, keysClient *keymanagement.Client) (*CaaSSignerVerifier, error) {
	if sk == nil {
		return nil, errors.New("invalid CaaS private key specified")
	}
	if cryptoClient == nil {
		return nil, errors.New("invalid CaaS crypto client specified")
	}
	if keysClient == nil {
		return nil, errors.New("invalid CaaS keys client specified")
	}
	signer := &CaaSSigner{
		ctx:          ctx,
		cryptoClient: cryptoClient,
		keysClient:   keysClient,
		sk:           sk,
	}
	verifier := &CaaSVerifier{
		ctx:          ctx,
		cryptoClient: cryptoClient,
		pk:           &CaaSPublicKey{keyName: sk.keyName},
	}
	return &CaaSSignerVerifier{
		CaaSSigner:   signer,
		CaaSVerifier: verifier,
	}, nil
}

type CaaSPrivateKey struct {
	keyName string
}

type CaaSPublicKey struct {
	keyName string
}

var _ gocrypto.PrivateKey = (*CaaSPrivateKey)(nil)
var _ gocrypto.PublicKey = (*CaaSPublicKey)(nil)

func (k *CaaSPublicKey) Equal(x gocrypto.PublicKey) bool {
	x0, ok := x.(*CaaSPublicKey)
	if !ok {
		return false
	}
	return k.keyName == x0.keyName
}

func (k *CaaSPrivateKey) Equal(x gocrypto.PrivateKey) bool {
	x0, ok := x.(*CaaSPrivateKey)
	if !ok {
		return false
	}
	return k.keyName == x0.keyName
}

func (k *CaaSPrivateKey) Public() gocrypto.PublicKey {
	return &CaaSPublicKey{
		keyName: k.keyName,
	}
}

type CaaSSigner struct {
	ctx          context.Context
	cryptoClient *crypto.Client
	keysClient   *keymanagement.Client
	sk           *CaaSPrivateKey
}

var _ Signer = (*CaaSSigner)(nil)

type signatureBundle struct {
	Signature []byte
	Metadata  *crypto.Metadata
}

func (s *signatureBundle) ToBytes() ([]byte, error) {
	if s.Metadata == nil {
		return s.Signature, nil
	}
	mdProto := s.Metadata.ToProto()
	mdBytes, err := proto.Marshal(mdProto)
	if err != nil {
		return nil, err
	}
	res := make([]byte, 0, len(s.Signature)+len(mdBytes)+4)
	sigSize := uint32(len(s.Signature))
	binary.BigEndian.PutUint32(res, sigSize)
	res = append(res, s.Signature...)
	res = append(res, mdBytes...)
	return res, nil
}

func (s *signatureBundle) FromBytes(data []byte) error {
	if len(data) < 4 {
		return errors.New("invalid signature bundle: size is missing")
	}
	sigSize := binary.BigEndian.Uint32(data[:4])
	if len(data) < int(4+sigSize) {
		return errors.New("invalid signature bundle: data is too short")
	}
	s.Signature = data[4 : 4+sigSize]
	if len(data) > int(4+sigSize) {
		mdBytes := data[4+sigSize:]
		mdProto := &messages.OperationMetadata{}
		if err := proto.Unmarshal(mdBytes, mdProto); err != nil {
			return err
		}
		s.Metadata = &crypto.Metadata{}
		s.Metadata.FromProto(mdProto)
	}
	return nil
}

func (s *CaaSSigner) PublicKey(opts ...PublicKeyOption) (gocrypto.PublicKey, error) {
	return s.sk.Public(), nil
}

func (s *CaaSSigner) SignMessage(message io.Reader, opts ...SignOption) ([]byte, error) {
	msgBytes, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}
	req := crypto.NewSignRequest(s.sk.keyName, msgBytes)
	res, err := s.cryptoClient.Sign(s.ctx, req)
	if err != nil {
		return nil, err
	}
	bundle := &signatureBundle{
		Signature: res.Signature(),
		Metadata:  res.Metadata(),
	}
	return bundle.ToBytes()
}

type CaaSVerifier struct {
	ctx          context.Context
	cryptoClient *crypto.Client
	pk           *CaaSPublicKey
}

var _ Verifier = (*CaaSVerifier)(nil)

func (s *CaaSVerifier) PublicKey(opts ...PublicKeyOption) (gocrypto.PublicKey, error) {
	return s.pk, nil
}

func (v *CaaSVerifier) VerifySignature(signature, message io.Reader, opts ...VerifyOption) error {
	sigBytes, err := io.ReadAll(signature)
	if err != nil {
		return err
	}
	bundle := &signatureBundle{}
	if err := bundle.FromBytes(sigBytes); err != nil {
		return err
	}
	msgBytes, err := io.ReadAll(message)
	if err != nil {
		return err
	}
	req := crypto.NewVerifyRequest(v.pk.keyName, msgBytes, bundle.Signature, bundle.Metadata)
	resp, err := v.cryptoClient.Verify(v.ctx, req)
	if err != nil {
		return err
	}
	if !resp.Valid() {
		return errors.New("invalid signature")
	}
	return nil
}

type CaaSSignerVerifier struct {
	*CaaSSigner
	*CaaSVerifier
}

var _ SignerVerifier = (*CaaSSignerVerifier)(nil)

func (sv *CaaSSignerVerifier) PublicKey(opts ...PublicKeyOption) (gocrypto.PublicKey, error) {
	return sv.CaaSSigner.PublicKey(opts...)
}
