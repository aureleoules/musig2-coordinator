package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"musig"
	"musig/coordinator"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.dedis.ch/kyber/v3"
)

var (
	pubKeySetFile string
	serverAddr    string
	keyFile       string
)

func init() {
	signCmd.Flags().StringVarP(&keyFile, "keyfile", "k", "./key", "key file")
	rootCmd.AddCommand(signCmd)

	signManyCmd.Flags().StringVarP(&pubKeySetFile, "pubkeys", "p", "", "public keys set of co-signers")
	signManyCmd.Flags().StringVarP(&serverAddr, "server", "s", "localhost:3555", "coordinator server address")
	signManyCmd.Flags().StringVarP(&keyFile, "keyfile", "k", "./key", "key file")
	rootCmd.AddCommand(signManyCmd)

	rootCmd.AddCommand(newKeysCmd)
}

var rootCmd = &cobra.Command{
	Use:   "musig",
	Short: "musig.",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var newKeysCmd = &cobra.Command{
	Use:   "newkey",
	Short: "Generate a new key pair.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := musig.NewKey()
		err := saveKey(key, args[0])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("Public key:", key.Pub.String())
	},
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a message locally.",

	Run: func(cmd *cobra.Command, args []string) {
		key, err := loadKey(keyFile)
		if err != nil {
			fmt.Println("no key", err)
			os.Exit(1)
		}
		sig := musig.Sign([]byte(args[0]), key)
		fmt.Println(hex.EncodeToString(sig.Encode()))
	},
}

var signManyCmd = &cobra.Command{
	Use:   "signmany",
	Short: "Sign a message with many co-signers.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		msg := []byte(args[0])

		d, err := ioutil.ReadFile(pubKeySetFile)
		if err != nil {
			fmt.Println("no such file")
			os.Exit(1)
		}
		keys := strings.Split(string(d), "\n")
		if len(keys) <= 1 {
			fmt.Println("requires more than 1 signer")
			return
		}

		var keySet []kyber.Point

		for _, k := range keys {
			if k == "" {
				continue
			}
			kb, err := hex.DecodeString(k)
			if err != nil {
				fmt.Println("invalid key")
				os.Exit(1)
			}

			key := musig.Curve().Point()
			if key.UnmarshalBinary(kb) != nil {
				fmt.Println("invalid key")
				os.Exit(1)
			}

			keySet = append(keySet, key)

		}
		key, err := loadKey(keyFile)
		coordinator.StartSession(serverAddr, keySet, msg, key)
	},
}
