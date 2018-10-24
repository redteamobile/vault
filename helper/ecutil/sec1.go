package ecutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/keybase/go-crypto/brainpool"
	"math/big"
)

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// ParseEcPrivateKey parses keys with named curves defined in x509
// and curves listed below:
//   brainpoolP256r1 - 1.3.36.3.3.2.8.1.1.7
//   FRP256V1 - 1.2.250.1.223.101.256.1
func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	var ecPrivKey *ecdsa.PrivateKey
	var err error
	ecPrivKey, err = x509.ParseECPrivateKey(der)
	if err != nil {
		ecPrivKey, err = parseSupplementaryCurvePrivateKey(der)
	}
	return ecPrivKey, err
}

// MarshalECPrivateKey marshals keys with named curves defined in x509
// and curves listed below:
//   brainpoolP256r1 - 1.3.36.3.3.2.8.1.1.7
//   FRP256V1 - 1.2.250.1.223.101.256.1
func MarshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	var der []byte
	var err error
	der, err = x509.MarshalECPrivateKey(key)
	if err != nil {
		der, err = marshalSupplementaryCurvePrivateKey(key)
	}
	return der, err
}

const ecPrivKeyVersion = 1

// parseSupplementaryCurvePrivateKey parsed an ASN1 Elliptic Private Key Structure.
// parsable curves listed below:
//   brainpoolP256r1 - 1.3.36.3.3.2.8.1.1.7
//   FRP256V1 - 1.2.250.1.223.101.256.1
func parseSupplementaryCurvePrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("ecutil: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("ecutil: unkown EC private key version %d", privKey.Version)
	}

	var curve elliptic.Curve
	curve = namedCurveFromOID(privKey.NamedCurveOID)
	if curve == nil {
		return nil, errors.New("ecutil: unkown elliptic curve")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("ecutil: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("ecutil: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)
	return priv, nil
}

func marshalSupplementaryCurvePrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	oid, ok := oidFromNamedCurve(key.Curve)
	if !ok {
		return nil, errors.New("ecutil: unknown elliptic curve")
	}

	privateKeyBytes := key.D.Bytes()
	paddedPrivateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)

	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

var (
	oidNamedCurveBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	odiNamedCurveFRP256V1        = asn1.ObjectIdentifier{1, 2, 250, 1, 223, 101, 256, 1}
)

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveBrainpoolP256r1):
		return brainpool.P256r1()
	case oid.Equal(odiNamedCurveFRP256V1):
		return FRP256v1()
	}
	return nil
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case brainpool.P256r1():
		return oidNamedCurveBrainpoolP256r1, true
	case FRP256v1():
		return odiNamedCurveFRP256V1, true
	}

	return nil, false
}
