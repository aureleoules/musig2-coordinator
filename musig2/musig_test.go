package musig2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
)

func TestSign(t *testing.T) {
	key := NewKey()
	msg := []byte("MuSig2")
	sig := Sign(msg, key)

	assert.True(t, VerifySignature(msg, sig, key.Pub))
}

type Signer struct {
	Key    *Key
	Nonces []*Key
}

func createSigner(noncesNum int) Signer {
	var nonces []*Key

	for j := 0; j < noncesNum; j++ {
		nonce := NewKey()
		nonces = append(nonces, nonce)
	}

	return Signer{
		Key:    NewKey(),
		Nonces: nonces,
	}
}

func TestManySigners(t *testing.T) {
	msg := []byte("MuSig2")

	signersNum := 20
	noncesNum := 3

	var signers []Signer

	var pubKeys []kyber.Point
	var publicNonces [][]kyber.Point
	for i := 0; i < signersNum; i++ {
		signer := createSigner(noncesNum)
		signers = append(signers, signer)

		pubKeys = append(pubKeys, signer.Key.Pub)

		var pubNonces []kyber.Point
		// first round
		for _, nonce := range signer.Nonces {
			pubNonces = append(pubNonces, nonce.Pub)
		}
		publicNonces = append(publicNonces, pubNonces)
	}

	var Rvalues []kyber.Point
	for j := 0; j < noncesNum; j++ {
		Rj := curve.Point().Null()
		for i := 0; i < len(publicNonces); i++ {
			Rj = curve.Point().Add(publicNonces[i][j], Rj)
		}
		Rvalues = append(Rvalues, Rj)
	}

	R := ComputeR(msg, Rvalues, pubKeys...)

	var sigs []kyber.Scalar
	for _, s := range signers {
		sigs = append(sigs, SignMulti(msg, s.Key, s.Nonces, R, Rvalues, pubKeys...))
	}
	sig := &Signature{
		R: R,
		S: AggregateSignatures(sigs...),
	}

	assert.True(t, VerifySignature(msg, sig, pubKeys...))
}
