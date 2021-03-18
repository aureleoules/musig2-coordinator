package coordinator

import (
	"net"

	musig "github.com/aureleoules/musig2-coordinator/musig2"

	server "github.com/aureleoules/go-packet-server"
	"go.dedis.ch/kyber/v3"
)

type Signer struct {
	PubKey     []byte
	Nonces     [][]byte
	PartialSig []byte

	conn *server.Session
}

type clientSigningSession struct {
	ID                []byte
	Message           []byte
	KeySet            []kyber.Point
	ExpectedCosigners uint16
	Pub               [32]byte
	Key               *musig.Key
	Signers           map[[32]byte]*Signer
	Nonces            []*musig.Key
	r                 kyber.Point

	partialSigsReceived int
	noncesReceived      int

	conn *net.TCPConn
}

type SigningSession struct {
	ID                  []byte
	ExpectedCosigners   uint16
	Signers             map[[32]byte]*Signer
	receivedPartialSigs int
}
