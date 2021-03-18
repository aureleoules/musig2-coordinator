package coordinator

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"musig"
	"net"

	server "github.com/aureleoules/go-packet-server"
	"go.dedis.ch/kyber/v3"
)

var conn *net.TCPConn
var session *SigningSession

func connect(addr string) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	conn, err = net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return err
	}

	return nil
}

func createConnectPacket(sessionID []byte, nCosigners uint16, key *musig.Key) *server.Packet {
	var payload bytes.Buffer

	payload.Write(sessionID)
	pKey, _ := key.Pub.MarshalBinary()
	payload.Write(pKey)

	var b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, nCosigners)
	payload.Write(b)

	sig := musig.Sign(payload.Bytes(), key).Encode()
	payload.Write(sig)

	p := server.NewPacket(ConnectSessionCommand)
	p.SetBytes(payload.Bytes())

	return p
}

func listen() {
	for {
		fmt.Println("Listening....")
		buffer := make([]byte, 1024)

		_, err := conn.Read(buffer)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("received packet")

		p := server.ToPacket(buffer[:buffer[0]])
		handlePacket(p)
	}
}

func handlePacket(p *server.Packet) {
	switch p.Type() {
	case SesssionReadyCommand:
		fmt.Println("Lets go!!!")
	case ConnectSessionCommand:
		// payload, err := extractPayload(p.Buffer())
		// if err != nil {
		// 	fmt.Println(err)
		// 	return
		// }
		// pubKey := extractPubKey(payload)

		// found := false
		// for _, p := range session.KeySet {
		// 	bin, _ := p.MarshalBinary()
		// 	if bytes.Equal(bin, pubKey[:]) {
		// 		found = true
		// 		break
		// 	}
		// }

		// if !found {
		// 	fmt.Println("pubkey not part of session")
		// 	return
		// }

		// signer := &Signer{
		// 	PubKey: pubKey[:],
		// }
		// session.Signers[pubKey] = signer
	}
}

func computeSessionID(keySet []kyber.Point, msg []byte) []byte {
	sum := musig.Curve().Point().Null()
	for _, k := range keySet {
		sum = musig.Curve().Point().Add(sum, k)
	}
	sumBytes, _ := sum.MarshalBinary()
	id := sha256.Sum256(append(sumBytes, msg...))
	return id[:]
}

func StartSession(addr string, keySet []kyber.Point, msg []byte, key *musig.Key) error {
	err := connect(addr)
	if err != nil {
		return err
	}

	sessionID := computeSessionID(keySet, msg)
	session = &SigningSession{
		ID:      sessionID,
		KeySet:  keySet,
		Signers: make(map[[32]byte]*Signer),
	}

	go listen()

	p := createConnectPacket(sessionID, uint16(len(keySet)), key)

	_, err = conn.Write(p.Buffer())
	if err != nil {
		return err
	}

	var str string
	for {
		fmt.Scanln(&str)
		if str == "q" {
			return nil
		}
	}
}
