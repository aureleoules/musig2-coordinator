package main

// func packetHeader(sessionID []byte, pub kyber.Point) []byte {
// 	b, _ := pub.MarshalBinary()
// 	return append(sessionID, b...)
// }

// func createNoncesPacket(sessionID []byte, pub kyber.Point, key *musig.Key, nonces ...*musig.Key) *server.Packet {
// 	var payload bytes.Buffer
// 	payload.Write(packetHeader(sessionID, pub))

// 	var b = make([]byte, 2)
// 	binary.BigEndian.PutUint16(b, uint16(len(nonces)))
// 	payload.Write(b)

// 	for _, r := range nonces {
// 		R, _ := r.Pub.MarshalBinary()
// 		payload.Write(R)
// 	}

// 	sig := musig.Sign(payload.Bytes(), key).Encode()
// 	payload.Write(sig)

// 	p := server.NewPacket(coordinator.BroadcastNoncesCommand)
// 	p.SetBytes(payload.Bytes())

// 	return p
// }
