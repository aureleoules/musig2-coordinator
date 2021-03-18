package main

import (
	"io/ioutil"
	"musig"
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
