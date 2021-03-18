package coordinator

import (
	"fmt"
	"os"

	server "github.com/aureleoules/go-packet-server"
)

var sessions = make(map[[32]byte]*SigningSession)

const (
	ConnectSessionCommand byte = iota
	SesssionReadyCommand
	BroadcastNoncesCommand
)

func Server() {
	s := server.New("localhost:3555")

	s.OnConnected(func(s *server.Session) {})
	s.OnDisconnected(func(s *server.Session) {})

	s.On(ConnectSessionCommand, func(s *server.Session, p *server.Packet) {
		payload, err := extractPayload(p.Buffer())
		if err != nil {
			fmt.Println(err)
			return
		}

		id := extractSessionID(payload)
		pub := extractPubKey(payload)
		nCosigners := extractExpectedCosigners(payload)

		signer := &Signer{
			PubKey: pub[:],
			conn:   s,
		}

		// Session does not exist
		// Create new one and insert Signer
		_, ok := sessions[id]
		if !ok {
			sess := &SigningSession{
				ID:                id[:],
				ExpectedCosigners: nCosigners,
			}
			sess.Signers = make(map[[32]byte]*Signer)
			sess.Signers[pub] = &Signer{
				PubKey: pub[:],
				conn:   s,
			}
			sessions[id] = sess
		} else {
			// Session already exists
			// Place signer
			sessions[id].Signers[pub] = signer
		}

		if int(nCosigners) == len(sessions[id].Signers) {
			for _, signer := range sessions[id].Signers {
				signer.conn.SendPacket(server.NewPacket(SesssionReadyCommand))
			}
		}
	})

	s.On(BroadcastNoncesCommand, func(s *server.Session, p *server.Packet) {
		// payload, err := extractPayload(p.Buffer())
		// if err != nil {
		// 	fmt.Println(err)
		// 	return
		// }

		// pub := extractPubKey(payload)
		// id := extractSessionID(payload)

		// nonces := extractNonces(payload)

		// for _, s := range sessions[id].Signers {
		// 	s.conn.SendPacket(p)
		// }
	})

	err := s.Start()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
