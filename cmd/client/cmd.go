package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/aureleoules/musig2-coordinator/coordinator"
	musig "github.com/aureleoules/musig2-coordinator/musig2"

	"github.com/spf13/cobra"
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

	verifyCmd.Flags().StringVarP(&pubKeySetFile, "pubkeys", "p", "", "public keys set of co-signers")
	rootCmd.AddCommand(verifyCmd)
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

		keySet, err := readKeySet(pubKeySetFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		key, err := loadKey(keyFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		coordinator.StartSession(serverAddr, keySet, msg, key)
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signature against one or more public keys",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 2 {
			fmt.Println("Not enough arguments.")
			os.Exit(1)
			return
		}
		msg := []byte(args[0])
		data, err := hex.DecodeString(args[1])
		if err != nil {
			fmt.Println("malformated signature")
		}
		sig, err := musig.DecodeSignature(data)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		var valid bool
		if pubKeySetFile != "" {
			keySet, err := readKeySet(pubKeySetFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			valid = musig.VerifySignature(msg, sig, keySet...)
		} else {
			if len(args) < 3 {
				fmt.Println("You must provide a public key.")
				os.Exit(1)
				return
			}
			pub, err := hex.DecodeString(args[2])
			if err != nil {
				fmt.Println("malformated pubkey")
				os.Exit(1)
			}
			p := musig.Curve().Point()
			p.UnmarshalBinary(pub)

			valid = musig.VerifySignature(msg, sig, p)
		}

		if valid {
			fmt.Println("Signature is valid.")
		} else {
			fmt.Println("Signature is invalid.")
		}
	},
}
