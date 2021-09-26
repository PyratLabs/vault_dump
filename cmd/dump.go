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

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	core "github.com/PyratLabs/vault_dump/core"
	kv "github.com/PyratLabs/vault_dump/kv"
	transit "github.com/PyratLabs/vault_dump/transit"
	"github.com/spf13/cobra"
)

// dumpCmd represents the dump command
var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump Vault to an encrypted JSON file",
	Run: func(cmd *cobra.Command, args []string) {
		runDump()
	},
}

func init() {
	rootCmd.AddCommand(dumpCmd)

	dumpCmd.PersistentFlags().StringSliceVarP(&core.KeyFile, "key", "k",
		nil, "gpg key(s) to use for encryption")

	dumpCmd.PersistentFlags().StringVarP(&core.OutFile, "file", "f",
		"", "output file for dump")

	dumpCmd.PersistentFlags().StringVarP(&core.KeyPass, "passphrase", "p",
		"", "passphrase for private key")

	dumpCmd.PersistentFlags().BoolVarP(&core.LogFmt, "json", "j",
		false, "print logs in JSON format")

	dumpCmd.PersistentFlags().BoolVarP(&core.Debug, "debug", "x",
		false, "enable debug output")
}

func dump() []byte {
	var dumpOut core.VaultDump
	core.Logger.Debug("dump() called")

	client, err := core.Authenticate()
	if err != nil {
		core.Logger.Error("failed to create vault client", "err", err)
		os.Exit(1)
	} else {
		core.Logger.Info("connected to vault", "VaultAddr", core.VaultAddr)
	}

	core.Logger.Debug("reading mounts")
	dumpOut.Address = core.VaultAddr
	dumpOut.Timestamp = time.Now().Unix()

	mounts, err := client.Sys().ListMounts()

	if err != nil {
		core.Logger.Error("could not read mounts", "err", err)
		os.Exit(1)
	} else {
		for path, mount := range mounts {
			core.Logger.Debug("mount found",
				"path", path,
				"type", mount.Type,
				"options", mount.Options)

			switch mount.Type {
			case "kv":
				core.Logger.Info("performing kv dump", "path", path)
				dumpOut.Mounts = append(dumpOut.Mounts,
					kv.DumpKvMount(client, path))
			case "transit":
				core.Logger.Info("performing transit key dump", "path", path)
				dumpOut.Mounts = append(dumpOut.Mounts,
					transit.DumpTransitMount(client, path))
			default:
				core.Logger.Warn("mount type not supported",
					"mount.Type", mount.Type)
			}
		}
	}

	jsonOut, err := json.Marshal(dumpOut)
	if err != nil {
		core.Logger.Error("cannot marshal vault dump", "err", err)
	}

	return jsonOut
}

func runDump() {
	core.Logger = core.CreateLogger("vault_dump", core.Debug, core.LogFmt)

	core.Logger.Debug("core.Logger created")
	core.Logger.Debug("run() called")

	if core.KeyFile == nil {
		core.Logger.Debug("empty key file path string",
			"file", core.KeyFile)
		core.Logger.Error("at least one key (--key|-k) is required to encrypt")
		os.Exit(1)
	}

	if core.OutFile == "" {
		core.Logger.Error("output file path required (--file|-f)")
		os.Exit(1)
	}

	core.Logger.Info("dump has been requested", "file", core.OutFile)

	core.IsRestore = false
	core.KeyRing = core.LoadKey()
	jsonOut := dump()

	core.Logger.Debug("starting encryption of json")

	out, err := core.KeyRing.Encrypt(crypto.NewPlainMessage(jsonOut), nil)
	if err != nil {
		core.Logger.Error("failed to encrypt dump output", "err", err)
		os.Exit(1)
	} else {
		core.Logger.Info("encrypted json file with keys",
			"keys", core.KeyFile)
	}

	output, err := out.GetArmored()
	if err != nil {
		core.Logger.Error("failed to get armoured dump output", "err", err)
		os.Exit(1)
	}

	wOErr := ioutil.WriteFile(core.OutFile, []byte(output), 0600)
	if wOErr != nil {
		core.Logger.Error("failed to write output file",
			"file", core.OutFile)
	} else {
		core.Logger.Info("backup file written",
			"file", core.OutFile)
	}

	core.Logger.Debug("end of command")
}
