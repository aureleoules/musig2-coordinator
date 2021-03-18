package coordinator

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	server "github.com/aureleoules/go-packet-server"
	"go.uber.org/zap"
)

var sessions = make(map[[32]byte]*SigningSession)

const (
	ConnectSessionCommand byte = iota
	SesssionReadyCommand
	BroadcastNoncesCommand
	BroadcastPartialSigCommand
)

func Server(port string) {
	s := server.New(":" + port)

	s.OnConnected(func(s *server.Session) {})
	s.OnDisconnected(func(s *server.Session) {

	})
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

		zap.S().Info(hex.EncodeToString(pub[:6]), " joined signing session.")

		if int(nCosigners) == len(sessions[id].Signers) {
			for _, signer := range sessions[id].Signers {
				signer.conn.SendPacket(server.NewPacket(SesssionReadyCommand))
			}
		}
	})

	s.On(BroadcastNoncesCommand, func(s *server.Session, p *server.Packet) {
		zap.S().Info("Received public nonces.")
		payload, err := extractPayload(p.Buffer())
		if err != nil {
			fmt.Println(err)
			return
		}

		id := extractSessionID(payload)
		pub := extractPubKey(payload)

		for _, signer := range sessions[id].Signers {
			if bytes.Equal(signer.PubKey, pub[:]) {
				continue
			}
			signer.conn.SendPacket(p)
		}
	})

	s.On(BroadcastPartialSigCommand, func(s *server.Session, p *server.Packet) {
		zap.S().Info("Received partial signature.")
		payload, err := extractPayload(p.Buffer())
		if err != nil {
			fmt.Println(err)
			return
		}

		id := extractSessionID(payload)
		pub := extractPubKey(payload)

		sessions[id].receivedPartialSigs++

		for _, signer := range sessions[id].Signers {
			if bytes.Equal(signer.PubKey, pub[:]) {
				continue
			}
			signer.conn.SendPacket(p)
		}

		if sessions[id].receivedPartialSigs == int(sessions[id].ExpectedCosigners) {
			delete(sessions, id)
		}
	})

	s.OnUnknownPacket(func(s *server.Session, p *server.Packet) {
		zap.S().Warn("Received unknown packet.")
	})

	zap.S().Info("MuSig2 coordinator started on :", port)
	err := s.Start()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
