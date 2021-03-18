package main

import (
	"encoding/hex"
	"errors"
	"io/ioutil"
	"strings"

	musig "github.com/aureleoules/musig2-coordinator/musig2"
	"go.dedis.ch/kyber/v3"
)

func saveKey(key *musig.Key, filename string) error {
	d, _ := key.Priv.MarshalBinary()
	return ioutil.WriteFile(filename, d, 0644)
}

func loadKey(filename string) (*musig.Key, error) {
	d, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	x := musig.Curve().Scalar().SetBytes(d)
	P := musig.Curve().Point().Mul(x, musig.Curve().Point().Base())

	return &musig.Key{
		Priv: x,
		Pub:  P,
	}, nil
}

func readKeySet(filename string) ([]kyber.Point, error) {
	d, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	keys := strings.Split(string(d), "\n")
	if len(keys) <= 1 {
		return nil, errors.New("requires more than 1 signer")
	}

	var keySet []kyber.Point
	for _, k := range keys {
		if k == "" {
			continue
		}
		kb, err := hex.DecodeString(k)
		if err != nil {
			return nil, errors.New("invalid key")
		}

		key := musig.Curve().Point()
		if key.UnmarshalBinary(kb) != nil {
			return nil, errors.New("invalid key")
		}

		keySet = append(keySet, key)
	}
	return keySet, nil
}
