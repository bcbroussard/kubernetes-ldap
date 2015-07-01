package token

import (
	"crypto/ecdsa"
	"fmt"

	pb "./proto"
	"github.com/golang/protobuf/proto"
	jose "github.com/square/go-jose"
)

type Issuer struct {
	signer *jose.Signer
	// LogToken is an optional user-provided function to log each
	// token that is issued. If nil, no logging is performed. It
	// should not panic, or cause an error.
	LogToken ([]byte)
}

const (
	curveName = "P-256"    // curveName is the name of the ECDSA curve
	curveJose = jose.ES256 // curveJose is the name of the JWS algorithm
)

// NewIssuer is, for the moment, a thin wrapper around Square's
// go-jose library to issue ECDSA-P256 JWS tokens.
func NewIssuer(key []byte) (iss *Issuer, err error) {
	// We use P-256, because Go has a constant-time implementation
	// of it. Go correctly checks that points are on the curve. A
	// version of Go > 1.4 is recommended, because ECDSA signatures
	// in previous versions are unsafe.
	privateKey, err := jose.LoadPrivateKey(key)
	if err != nil {
		return
	}
	// TODO(dlg): Once JOSE supports it, make sure that this works for curve25519
	// Check that it's actually an ECDSA key,
	ecdsaKey, ok := privateKey.(ecdsa.PrivateKey)
	if !ok {
		err = fmt.Errorf("expected an ECDSA private key, but got a key of type %T", privateKey)
		return
	}
	// and that it's on the expected curve.
	if ecdsaKey.Params().Name != curveName {
		err = fmt.Errorf("expected the key to use %s, but it's using %s", curveName, ecdsaKey.Params().Name)
	}

	signer, err := jose.NewSigner(curveJose, privateKey)
	if err != nil {
		return
	}
	iss = &Issuer{
		signer: &signer,
	}
	return
}

// Issue issues a new, signed token, logging it to iss.LogToken
// if that's non-nil.
func (iss *Issuer) Issue(token *pb.Token) (token []byte, err error) {
	b, err := proto.Marshal(token)
	if err != nil {
		// panic? what are the conditions under which this can fail?
		return err
	}
	jws, err := iss.signer.Sign(token)
	if err != nil {
		return
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		return
	}
	iss.LogToken([]byte(s))
	return []byte(s)
}

// Verify checks that a token is valid.
