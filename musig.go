package musig

import (
	"crypto/sha256"
	"encoding/binary"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
)

var curve = suites.MustFind("Ed25519")

func Curve() suites.Suite {
	return curve
}

type Signature struct {
	R kyber.Point
	S kyber.Scalar
}

type Key struct {
	Priv kyber.Scalar
	Pub  kyber.Point
}

func (s *Signature) Encode() []byte {
	return append(encodePoint(s.R), encodeScalar(s.S)...)
}

func Sign(msg []byte, key *Key) *Signature {
	r := NewKey()

	return &Signature{
		R: r.Pub,
		S: SignMulti(msg, key, []*Key{r}, r.Pub, []kyber.Point{r.Pub}, key.Pub),
	}
}

func SignMulti(msg []byte, key *Key, nonces []*Key, R kyber.Point, RValues []kyber.Point, pubKeys ...kyber.Point) kyber.Scalar {
	L := computeL(pubKeys...)
	X := computeX(L, pubKeys...)
	c := computeC(X, R, msg)

	a := computeA(L, key.Pub)
	ax := curve.Scalar().Mul(a, key.Priv)
	axc := curve.Scalar().Mul(c, ax)

	sum := curve.Scalar()
	for j, n := range nonces {
		b := computeB(uint64(j), msg, RValues, pubKeys...)
		sum = curve.Scalar().Add(sum, curve.Scalar().Mul(b, n.Priv))
	}

	return curve.Scalar().Add(sum, axc)
}

func VerifySignature(msg []byte, sig *Signature, pubKeys ...kyber.Point) bool {
	L := computeL(pubKeys...)
	X := computeX(L, pubKeys...)
	c := computeC(X, sig.R, msg)

	proof := curve.Point().Add(X.Mul(c, X), sig.R)
	sG := curve.Point().Mul(sig.S, curve.Point().Base())

	return proof.Equal(sG)
}

func AggregateSignatures(sigs ...kyber.Scalar) kyber.Scalar {
	s := curve.Scalar()
	for _, sig := range sigs {
		s = curve.Scalar().Add(s, sig)
	}
	return s
}

func computeR(msg []byte, RValues []kyber.Point, pubKeys ...kyber.Point) kyber.Point {
	R := curve.Point().Null()
	for j, Rj := range RValues {
		b := computeB(uint64(j), msg, RValues, pubKeys...)
		R = curve.Point().Add(R, curve.Point().Mul(b, Rj))
	}
	return R
}

func computeB(j uint64, msg []byte, nonces []kyber.Point, pubKeys ...kyber.Point) kyber.Scalar {
	if j == 0 {
		return curve.Scalar().SetInt64(1)
	}

	L := computeL(pubKeys...)
	X := computeX(L, pubKeys...)

	var bBytes []byte

	// encode j
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, j)

	bBytes = append(bBytes, b...)
	bBytes = append(bBytes, encodePoint(X)...)
	for _, n := range nonces {
		bBytes = append(bBytes, encodePoint(n)...)
	}
	bBytes = append(bBytes, msg...)

	return curve.Scalar().SetBytes(bBytes)
}

func computeA(L []byte, X kyber.Point) kyber.Scalar {
	p, _ := X.MarshalBinary()
	hash := sha256.Sum256(append(L, p...))
	return curve.Scalar().SetBytes(hash[:])
}

func computeC(X, R kyber.Point, msg []byte) kyber.Scalar {
	h := sha256.Sum256(append(encodePoint(X), append(encodePoint(R), msg...)...))
	return curve.Scalar().SetBytes(h[:])
}

func computeX(L []byte, pubKeys ...kyber.Point) kyber.Point {
	X := curve.Point().Null()

	for _, p := range pubKeys {
		ap := curve.Point().Mul(computeA(L, p), p)
		X = curve.Point().Add(X, ap)
	}

	return X
}

func computeL(pubKeys ...kyber.Point) []byte {
	var data []byte
	for _, p := range pubKeys {
		b, _ := p.MarshalBinary()
		data = append(data, b...)
	}

	h := sha256.Sum256(data)
	return h[:]
}

func NewKey() *Key {
	x := curve.Scalar().Pick(curve.RandomStream())
	P := curve.Point().Mul(x, curve.Point().Base())

	return &Key{
		Priv: x,
		Pub:  P,
	}
}

func encodePoint(p kyber.Point) []byte {
	b, _ := p.MarshalBinary()
	return b
}
func encodeScalar(s kyber.Scalar) []byte {
	b, _ := s.MarshalBinary()
	return b
}
