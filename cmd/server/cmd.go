package main

import (
	"github.com/aureleoules/musig2-coordinator/coordinator"
	"github.com/spf13/cobra"
)

var port string

func init() {
	startCmd.Flags().StringVarP(&port, "port", "p", "3555", "coordinator server port")
	rootCmd.AddCommand(startCmd)
}

var rootCmd = &cobra.Command{
	Use:   "musig",
	Short: "musig.",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start musig coordinator server.",
	Run: func(cmd *cobra.Command, args []string) {
		coordinator.Server(port)
	},
}
