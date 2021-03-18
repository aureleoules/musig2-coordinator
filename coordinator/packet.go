package coordinator

import (
	"bytes"
	"encoding/binary"
	"errors"

	server "github.com/aureleoules/go-packet-server"
	musig "github.com/aureleoules/musig2-coordinator/musig2"
	"go.dedis.ch/kyber/v3"
)

func packetHeader(sessionID []byte, pub kyber.Point) []byte {
	b, _ := pub.MarshalBinary()
	return append(sessionID, b...)
}

func createConnectPacket(s *clientSigningSession) *server.Packet {
	var payload bytes.Buffer
	payload.Write(packetHeader(s.ID, s.Key.Pub))

	var b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, s.ExpectedCosigners)
	payload.Write(b)

	sig := musig.Sign(payload.Bytes(), s.Key).Encode()
	payload.Write(sig)

	p := server.NewPacket(ConnectSessionCommand)
	p.SetBytes(payload.Bytes())

	return p
}

func createNoncesPacket(s *clientSigningSession, nonces ...*musig.Key) *server.Packet {
	var payload bytes.Buffer
	payload.Write(packetHeader(s.ID, s.Key.Pub))

	var b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(nonces)))
	payload.Write(b)

	for _, r := range nonces {
		R, _ := r.Pub.MarshalBinary()
		payload.Write(R)
	}

	sig := musig.Sign(payload.Bytes(), s.Key).Encode()
	payload.Write(sig)

	p := server.NewPacket(BroadcastNoncesCommand)
	p.SetBytes(payload.Bytes())

	return p
}

func createPartialSigPacket(s *clientSigningSession, partialSig []byte) *server.Packet {
	var payload bytes.Buffer
	payload.Write(packetHeader(s.ID, s.Key.Pub))

	payload.Write(partialSig)

	sig := musig.Sign(payload.Bytes(), s.Key).Encode()
	payload.Write(sig)

	p := server.NewPacket(BroadcastPartialSigCommand)
	p.SetBytes(payload.Bytes())

	return p
}

func extractSessionID(data []byte) [32]byte {
	var id [32]byte
	copy(id[:], data[:32])
	return id
}
func extractPubKey(payload []byte) [32]byte {
	var pub [32]byte
	copy(pub[:], payload[32:64])
	return pub
}

func extractExpectedCosigners(payload []byte) uint16 {
	return binary.BigEndian.Uint16(payload[64:66])
}

func extractPayload(data []byte) ([]byte, error) {
	RB := data[len(data)-64 : len(data)-32]
	sB := data[len(data)-32:]

	R := musig.Curve().Point()
	R.UnmarshalBinary(RB)

	S := musig.Curve().Scalar().SetBytes(sB)

	payload := data[3 : len(data)-64]

	p := musig.Curve().Point()
	pub := extractPubKey(payload)
	p.UnmarshalBinary(pub[:])

	if !musig.VerifySignature(payload, &musig.Signature{
		R: R,
		S: S,
	}, p) {
		return nil, errors.New("invalid signature")
	}

	return payload, nil
}

func extractNonces(payload []byte) [][]byte {
	offset := 64 // skip id & pubkey
	n := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	var nonces [][]byte
	for i := 0; i < int(n); i++ {
		nonces = append(nonces, payload[offset:offset+32])
		offset += 32
	}

	return nonces
}

func extractPartialSig(payload []byte) []byte {
	return payload[64 : 64+32]
}
