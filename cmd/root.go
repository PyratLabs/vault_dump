/*
Copyright © 2021 Xan Manning <xan@manning.io>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
package cmd

// docker run --rm --cap-add=IPC_LOCK -d -p 127.0.0.1:8201:8200 --name=dev-vault vault:1.8.2

import (
	"fmt"
	"os"

	core "github.com/PyratLabs/vault_dump/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	hclog "github.com/hashicorp/go-hclog"
)

var (
	gitHash     string
	showVersion bool
	version     string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vault_dump",
	Short: "Dump and restore secrets from Hashicorp Vault",
	Run: func(cmd *cobra.Command, args []string) {
		run()
		fmt.Println("vault_dump")
		fmt.Println("----------")
		fmt.Printf("  %s\n\n", cmd.Short)
		cmd.Usage()
	},
}

func Execute(mainVersion string, mainGitHash string) {
	version = mainVersion
	gitHash = mainGitHash

	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	viper.AutomaticEnv()

	rootCmd.PersistentFlags().BoolVarP(&core.LogFmt, "json", "j",
		false, "print logs in JSON format")

	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v",
		false, "show vault_dump version")

	rootCmd.PersistentFlags().BoolVarP(&core.Debug, "debug", "x",
		false, "enable debug output")

	core.IsRestore = false
}

func run() {
	var logLevel string

	if core.Debug {
		logLevel = "DEBUG"
	} else {
		logLevel = "INFO"
	}

	core.Logger = hclog.New(&hclog.LoggerOptions{
		Name:       "vault_dump",
		Level:      hclog.LevelFromString(logLevel),
		JSONFormat: core.LogFmt,
		Color:      hclog.AutoColor,
	})

	if showVersion {
		core.Logger.Info("created by Xan Manning",
			"version", version, "git-hash", gitHash)
		os.Exit(0)
	}

	core.Logger.Debug("core.Logger created")
	core.Logger.Debug("run() called")

	core.Logger.Debug("Usage() called")

	core.Logger.Debug("end of command")
}
