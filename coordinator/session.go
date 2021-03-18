package coordinator

import (
	server "github.com/aureleoules/go-packet-server"
	"go.dedis.ch/kyber/v3"
)

type Signer struct {
	PubKey []byte
	Nonces [][]byte

	conn *server.Session
}

type SigningSession struct {
	ID                []byte
	KeySet            []kyber.Point
	ExpectedCosigners uint16
	Signers           map[[32]byte]*Signer
}
