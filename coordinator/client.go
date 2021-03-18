package coordinator

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"

	musig "github.com/aureleoules/musig2-coordinator/musig2"
	"go.uber.org/zap"

	server "github.com/aureleoules/go-packet-server"
	"go.dedis.ch/kyber/v3"
)

func connect(addr string) (*net.TCPConn, error) {
	zap.S().Info("Connecting to ", addr, ".")
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil, err
	}
	zap.S().Info("Connected to ", addr, ".")
	return conn, nil
}

func listen(s *clientSigningSession) {
	for {
		zap.S().Debug("Listening...")
		buffer := make([]byte, 1024)

		_, err := s.conn.Read(buffer)
		if err != nil {
			fmt.Println(err)
		}
		zap.S().Debug("Received packet.")

		p := server.ToPacket(buffer[:buffer[0]])
		handlePacket(p, s)
	}
}

func handlePacket(p *server.Packet, s *clientSigningSession) {
	switch p.Type() {
	case SesssionReadyCommand:
		zap.S().Info("Signing session is ready.")
		p := createNoncesPacket(s, s.Nonces...)
		zap.S().Info("Broadcasting public nonces...")
		_, err := s.conn.Write(p.Buffer())
		if err != nil {
			zap.S().Fatal(err)
			return
		}
		zap.S().Info("Broadcasted public nonces.")

	case BroadcastNoncesCommand:
		zap.S().Info("Received nonces from co-signer.")
		payload, err := extractPayload(p.Buffer())
		if err != nil {
			fmt.Println(err)
			return
		}
		pubKey := extractPubKey(payload)

		found := false
		for _, p := range s.KeySet {
			bin, _ := p.MarshalBinary()
			if bytes.Equal(bin, pubKey[:]) {
				found = true
				break
			}
		}

		if !found {
			zap.S().Warn("Signer's public key not part of key set.")
			return
		}

		signer := &Signer{
			PubKey: pubKey[:],
			Nonces: extractNonces(payload),
		}

		s.Signers[pubKey] = signer
		s.noncesReceived++

		if s.noncesReceived == int(s.ExpectedCosigners)-1 {
			zap.S().Info("All nonces received.")
			computePartialSig(s)
		}

	case BroadcastPartialSigCommand:
		zap.S().Info("Received partial signature from co-signer.")

		payload, err := extractPayload(p.Buffer())
		if err != nil {
			fmt.Println(err)
			return
		}
		pubKey := extractPubKey(payload)
		partialSig := extractPartialSig(payload)
		s.Signers[pubKey].PartialSig = partialSig
		s.partialSigsReceived++

		if s.partialSigsReceived == int(s.ExpectedCosigners)-1 {
			zap.S().Info("All partial signatures received.")
			var sigs []kyber.Scalar
			for _, signer := range s.Signers {
				sigs = append(sigs, musig.Curve().Scalar().SetBytes(signer.PartialSig))
			}
			finalSig := &musig.Signature{
				R: s.r,
				S: musig.AggregateSignatures(sigs...),
			}

			fmt.Println(hex.EncodeToString(finalSig.Encode()))
			zap.S().Info("Closing signing session...")
			s.conn.Close()
			os.Exit(0)
		}
	}
}

func computePartialSig(s *clientSigningSession) {
	var Rvalues []kyber.Point
	for j := 0; j < 2; j++ {
		Rj := musig.Curve().Point().Null()
		for _, signer := range s.Signers {
			r := musig.Curve().Point()
			r.UnmarshalBinary(signer.Nonces[j])
			Rj = musig.Curve().Point().Add(r, Rj)
		}
		Rvalues = append(Rvalues, Rj)
	}

	s.r = musig.ComputeR(s.Message, Rvalues, s.KeySet...)

	sig := musig.SignMulti(s.Message, s.Key, s.Nonces, s.r, Rvalues, s.KeySet...)
	sigBytes, _ := sig.MarshalBinary()

	s.Signers[s.Pub].PartialSig = sigBytes
	p := createPartialSigPacket(s, sigBytes)

	zap.S().Info("Broadcasting partial signature...")
	_, err := s.conn.Write(p.Buffer())
	if err != nil {
		zap.S().Fatal(err)
		return
	}
	zap.S().Info("Broadcasted partial signature.")
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
	zap.S().Info("Creating signing session with ", len(keySet), " co-signers.\nSigning: ", string(msg))

	conn, err := connect(addr)
	if err != nil {
		return err
	}

	var pub [32]byte
	b, _ := key.Pub.MarshalBinary()
	copy(pub[:], b)

	s := &clientSigningSession{
		ID:                computeSessionID(keySet, msg),
		Message:           msg,
		KeySet:            keySet,
		Signers:           make(map[[32]byte]*Signer),
		ExpectedCosigners: uint16(len(keySet)),
		Pub:               pub,
		Key:               key,
		Nonces:            []*musig.Key{musig.NewKey(), musig.NewKey()},

		conn: conn,
	}

	var nonces [][]byte
	for _, n := range s.Nonces {
		nb, _ := n.Pub.MarshalBinary()
		nonces = append(nonces, nb)
	}

	s.Signers[pub] = &Signer{
		PubKey: pub[:],
		Nonces: nonces,
	}

	go listen(s)

	p := createConnectPacket(s)
	zap.S().Info("Connecting to signing session...")
	_, err = s.conn.Write(p.Buffer())
	if err != nil {
		return err
	}
	zap.S().Info("Connected to signing session [", hex.EncodeToString(s.ID), "].")

	var str string
	for {
		fmt.Scanln(&str)
		if str == "q" {
			return nil
		}
	}
}
