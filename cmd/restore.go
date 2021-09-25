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
	"sort"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	core "github.com/PyratLabs/vault_dump/core"
	kv "github.com/PyratLabs/vault_dump/kv"
	transit "github.com/PyratLabs/vault_dump/transit"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/spf13/cobra"
)

// restoreCmd represents the restore command
var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore an encrypted JSON dump to Vault",
	Run: func(cmd *cobra.Command, args []string) {
		runRestore()
	},
}

func init() {
	rootCmd.AddCommand(restoreCmd)

	restoreCmd.PersistentFlags().StringVarP(&core.KeyFile, "key", "k",
		"", "gpg key to use (private key required for decryption)")

	restoreCmd.PersistentFlags().StringVarP(&core.InFile, "file", "f",
		"", "input file for restore")

	restoreCmd.PersistentFlags().BoolVarP(&core.IgnoreAddress,
		"ignore-address", "i", false, "ignore mismatched restore address")

	restoreCmd.PersistentFlags().StringVarP(&core.KeyPass, "passphrase", "p",
		"", "passphrase for private key")

	restoreCmd.PersistentFlags().BoolVarP(&core.LogFmt, "json", "j",
		false, "print logs in JSON format")

	restoreCmd.PersistentFlags().BoolVarP(&core.Debug, "debug", "x",
		false, "enable debug output")
}

func restore(dump []byte) {
	var mounts []string
	var dumpIn core.VaultDump

	core.Logger.Debug("restore() called")
	core.Logger.Debug("unmarshal of dump started")

	jsonErr := json.Unmarshal(dump, &dumpIn)
	if jsonErr != nil {
		core.Logger.Error("failed to unmarshal dump", "err", jsonErr)
	}

	if (dumpIn.Address != core.EVaultAddr) && !core.IgnoreAddress {
		core.Logger.Error("VAULT_ADDR does not match address in dump file",
			"address", dumpIn.Address, "VAULT_ADDR", core.EVaultAddr)
		core.Logger.Error("to continue use --ignore-address")
		os.Exit(1)
	}

	client, err := core.Authenticate()
	if err != nil {
		core.Logger.Error("failed to create vault client", "err", err)
	} else {
		core.Logger.Info("connected to vault", "VaultAddr", core.VaultAddr)
	}

	mountsList, err := client.Sys().ListMounts()
	mounts = make([]string, len(mountsList))
	if err != nil {
		core.Logger.Error("could not list mounts", "err", err)
		os.Exit(1)
	}

	i := 0
	for k := range mountsList {
		mounts[i] = k
		i++
	}

	for _, m := range dumpIn.Mounts {
		sort.Strings(mounts)
		mountSearch := sort.SearchStrings(mounts, m.Mount)
		mountExists := (mountSearch < len(mounts) &&
			mounts[mountSearch] == m.Mount)
		core.Logger.Debug("searching for mount", "mount", m.Mount,
			"found", mountExists)

		if mountExists {
			core.Logger.Info("restoring mount point", "mount", m.Mount)
			switch m.Type {
			case "kv":
				core.Logger.Debug("mount is a kv", "mount", m.Mount)
				kv.RestoreKvMount(client, m.Mount, m.Paths)
			case "transit":
				core.Logger.Debug("mount is a transit", "mount", m.Mount)
				transit.RestoreTransitMount(client, m.Mount, m.Paths)
			default:
				core.Logger.Warn("unsupported mount type", "type", m.Type)
			}
		} else {
			core.Logger.Warn("could not find mount point", "mount", m.Mount)
		}
	}
}

func runRestore() {
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

	core.Logger.Debug("core.Logger created")
	core.Logger.Debug("run() called")

	if core.KeyFile == "" {
		core.Logger.Debug("empty key file path string",
			"KeyFile", core.KeyFile)
		core.Logger.Error("--key needs and argument")
		os.Exit(1)
	}

	if core.InFile == "" {
		core.Logger.Error("input file path required (--file|-f)")
		os.Exit(1)
	}

	core.Logger.Info("restore has been requested", "file", core.InFile)

	core.IsRestore = true
	core.KeyRing = core.LoadKey()

	encDump, err := ioutil.ReadFile(core.InFile)
	if err != nil {
		core.Logger.Error("cannot read input file", "file",
			core.InFile, "err", err)
		os.Exit(1)
	} else {
		core.Logger.Info("encrypted input file read", "file", core.InFile)
	}

	encMessage, err := crypto.NewPGPMessageFromArmored(string(encDump))
	if err != nil {
		core.Logger.Error("failed to parse ciphertext", "err", err)
		os.Exit(1)
	}

	dumpContent, err := core.KeyRing.Decrypt(encMessage, nil, 0)
	if err != nil {
		core.Logger.Error("failed decrypting input dump file",
			"file", core.InFile, "err", err)
		os.Exit(1)
	} else {
		core.Logger.Info("decrypted input dump file", "file", core.InFile)
	}

	restore([]byte(dumpContent.GetString()))

	core.Logger.Debug("end of command")
}
