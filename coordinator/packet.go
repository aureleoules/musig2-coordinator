package coordinator

import (
	"encoding/binary"
	"errors"
	"musig"
)

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
