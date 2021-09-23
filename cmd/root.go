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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/prometheus/common/log"
	"github.com/spf13/cobra"

	"github.com/spf13/viper"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	hclog "github.com/hashicorp/go-hclog"
	vault "github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
)

var (
	action        string
	debug         bool
	ePassPhrase   string = os.Getenv("VAULT_DUMP_PASSPHRASE")
	eVaultAddr    string = os.Getenv("VAULT_ADDR")
	eVaultToken   string = os.Getenv("VAULT_TOKEN")
	gitHash       string
	ignoreAddress bool
	inFile        string
	keyFile       string
	keyRing       crypto.KeyRing
	keyPass       string
	logFmt        bool
	logger        hclog.Logger
	showVersion   bool
	outFile       string
	vaultAddr     string
	vaultToken    string
	version       string
)

type kvSecretDump struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type transitSecretDump struct {
	Backup string `json:"backup"`
}

type pathDump struct {
	Path         string            `json:"path"`
	Kv_secrets   []kvSecretDump    `json:"kv_secrets"`
	Transit_keys transitSecretDump `json:"transit_keys"`
}

type mountDump struct {
	Mount string     `json:"mount"`
	Type  string     `json:"type"`
	Paths []pathDump `json:"paths"`
}

type vaultDump struct {
	Timestamp int64       `json:"timestamp"`
	Address   string      `json:"address"`
	Mounts    []mountDump `json:"mounts"`
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vault_dump",
	Short: "Dump and restore secrets from Hashicorp Vault",
	Run: func(cmd *cobra.Command, args []string) {
		run()
	},
}

func Execute(mainVersion string, mainGitHash string) {
	version = mainVersion
	gitHash = mainGitHash

	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	viper.AutomaticEnv()

	rootCmd.PersistentFlags().StringVarP(&action, "action", "a",
		"", "action to take (either 'dump' or 'restore')")

	rootCmd.PersistentFlags().StringVarP(&keyFile, "key", "k",
		"", "gpg key to use (private key required for decryption)")

	rootCmd.PersistentFlags().StringVarP(&outFile, "output", "o",
		"", "output file for dump")

	rootCmd.PersistentFlags().StringVarP(&inFile, "input", "i",
		"", "input file for restore")

	rootCmd.PersistentFlags().StringVarP(&keyPass, "passphrase", "p",
		"", "passphrase for private key")

	rootCmd.PersistentFlags().BoolVarP(&logFmt, "json", "j",
		false, "print logs in JSON format")

	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "x",
		false, "enable debug output")

	rootCmd.PersistentFlags().BoolVarP(&ignoreAddress, "ignore-address", "g",
		false, "ignore mismatched restore address")

	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v",
		false, "show vault_dump version")
}

func marshalUnmarshal(data interface{}, structure interface{}) error {
	var emptyErr error
	logger.Debug("marshalUnmarshal() called")

	jsonOut, marshalErr := json.Marshal(data)
	if marshalErr != nil {
		return marshalErr
	}

	unmarshalErr := json.Unmarshal(jsonOut, &structure)
	if unmarshalErr != nil {
		return unmarshalErr
	}

	return emptyErr
}

func loadKey() crypto.KeyRing {
	var keyObjUnlocked *crypto.Key

	logger.Debug("loadKey() called")
	logger.Debug("loading key file")

	if keyPass == "" && ePassPhrase != "" {
		keyPass = ePassPhrase
	}

	raw_key, err := ioutil.ReadFile(keyFile)

	if err != nil {
		logger.Error("unable to read file", "key", keyFile, "err", err)
		os.Exit(1)
	}

	keyObj, err := crypto.NewKeyFromArmored(string(raw_key))

	if err != nil {
		logger.Error("unable to read key", "key", keyFile, "err", err)
		os.Exit(1)
	}

	if keyObj.IsPrivate() {
		logger.Debug("private key loaded: can encrypt and decrypt")
		isLocked, err := keyObj.IsLocked()
		if err != nil {
			logger.Error("unable to determine if key is locked", "err", err)
			os.Exit(1)
		}
		if isLocked {
			logger.Debug("key information", "locked", "true")

			if keyPass == "" {
				logger.Error("cannot unlock key," +
					"no passphrase specified" +
					"(--passphrase|-p|VAULT_DUMP_PASSPHRASE)")
				os.Exit(1)
			}

			keyObjUnlocked, err = keyObj.Unlock([]byte(keyPass))
			if err != nil {
				logger.Error("unable to unlock key", "err", err)
				os.Exit(1)
			}

			logger.Debug("key unlocked")
		} else {
			keyObjUnlocked = keyObj
		}
	} else {
		logger.Debug("public key loaded: can encrypt only")
		if action == "restore" {
			logger.Error("key file is a public key, cannot decrypt vault dump",
				"keyFile", keyFile)
			os.Exit(1)
		}
		keyObjUnlocked = keyObj
	}

	if keyObjUnlocked.IsExpired() {
		logger.Warn("key has expired")
	}

	logger.Debug("key information", "fingerprint",
		keyObjUnlocked.GetFingerprint())
	logger.Debug("key information", "id",
		keyObjUnlocked.GetKeyID())
	logger.Debug("key information", "hex",
		keyObjUnlocked.GetHexKeyID())

	keyRing, err := crypto.NewKeyRing(keyObjUnlocked)

	if err != nil {
		logger.Error("cannot create key ring", "err", err)
		os.Exit(1)
	}

	return *keyRing
}

func authenticate() (*vault.Client, error) {
	logger.Debug("authenticate() called")

	if eVaultAddr != "" {
		vaultAddr = eVaultAddr
		logger.Debug("VAULT_ADDR defined", "vaultAddr", vaultAddr)
	} else {
		vaultAddr = "http://localhost:8200"
		logger.Debug("VAULT_ADDR undefined, using default",
			"vaultAddr", vaultAddr)
	}

	if eVaultToken != "" {
		vaultToken = eVaultToken
		logger.Debug("VAULT_TOKEN defined", "vaultToken", vaultToken)
	} else {
		home, err := homedir.Dir()

		if err != nil {
			logger.Warn("cannot determine home directory")
		}

		fileToken, err := ioutil.ReadFile(
			fmt.Sprintf("%s/.vault-token", home))

		if err != nil {
			logger.Warn("failed to open token file", "err", err)
		} else {
			vaultToken = string(fileToken)
		}
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	logger.Debug("creating vault client",
		"vaultAddr", vaultAddr, "vaultToken", vaultToken)

	client, err := vault.NewClient(&vault.Config{
		Address:    vaultAddr,
		HttpClient: httpClient,
	})

	client.SetToken(vaultToken)

	return client, err
}

func listKvSecrets(client *vault.Client, mount string) []string {
	var keys *vault.Secret
	var kvPath string
	var kv2Path string
	var outPaths []string
	var pathCheck string
	var reSearch *regexp.Regexp
	var reReplace string
	var vPrefix string

	logger.Debug("listKvSecrets() called")

	reSearch = regexp.MustCompile("^(.*?)/")
	reReplace = "${1}/metadata/$2"
	kvPath = mount
	kv2Path = reSearch.ReplaceAllString(mount, reReplace)

	var secretPaths struct {
		Paths []string `json:"keys"`
	}

	logger.Debug("reading path", "kvPath", kvPath)
	kvkeys, kverr := client.Logical().List(kvPath)
	logger.Debug("results found with v1 list", "results", len(kvkeys.Data))
	if kverr != nil {
		log.Error("could not list paths", "mount", mount, "err", kverr)
	}

	if len(kvkeys.Data) < 1 {
		logger.Debug("could not find v1 secret, trying v2", "kv2Path", kv2Path)
		kv2keys, kv2err := client.Logical().List(kv2Path)
		if kv2err != nil {
			logger.Error("count not list paths", "mount", mount, "err", kv2err)
		}
		keys = kv2keys
		vPrefix = "v2"
	} else {
		logger.Debug("could not find v2 secret, trying v1", "kvPath", kvPath)
		keys = kvkeys
		vPrefix = "v1"
	}

	if keys != nil {
		munErr := marshalUnmarshal(keys.Data, &secretPaths)
		if munErr != nil {
			logger.Error("json marshal/unmarshal failed", "err", munErr)
		}

		for _, p := range secretPaths.Paths {
			pathCheck = p[len(p)-1:]
			newPath := fmt.Sprintf("%s%s", mount, p)
			returnPath := fmt.Sprintf("%s:%s", vPrefix, newPath)
			if pathCheck == "/" {
				logger.Debug("path found", "path", p)
				outPaths = append(outPaths, listKvSecrets(client, newPath)...)
				if outPaths == nil {
					logger.Error("could not read path", "path", newPath)
				}

			} else {
				outPaths = append(outPaths, returnPath)
			}
		}
	}

	return outPaths
}

func dumpKvMount(client *vault.Client, mount string) mountDump {
	var output mountDump
	var outputPath pathDump
	var outputSecret kvSecretDump
	var secVer string
	var secPath string
	var sec2Path string
	var secList []string
	var verSearch *regexp.Regexp
	var verSplit []string
	var secSearch *regexp.Regexp
	var secReplace string

	var kvSecret map[string]string
	var kv2Secret struct {
		Data map[string]string `json:"data"`
	}

	logger.Debug("dumpKvMount() called")

	output.Mount = mount
	output.Type = "kv"

	secList = listKvSecrets(client, mount)

	logger.Debug("secrets list generated", "secList", secList)

	for _, sec := range secList {
		verSearch = regexp.MustCompile(":")
		verSplit = verSearch.Split(sec, 2)
		secVer = verSplit[0]
		secPath = verSplit[1]
		secSearch = regexp.MustCompile("^(.*?)/")
		secReplace = "${1}/data/${2}"
		sec2Path = secSearch.ReplaceAllString(verSplit[1], secReplace)

		logger.Info("backing up kv path", "mount", mount,
			"path", secPath, "version", secVer)

		outputPath.Path = secPath

		switch secVer {
		case "v1":
			readsec, readerr := client.Logical().Read(secPath)
			if readerr != nil {
				logger.Error("cannot read v1 secret path", "path", secPath)
			}

			munErr := marshalUnmarshal(readsec.Data, &kvSecret)
			if munErr != nil {
				logger.Error("json marshal/unmarshal failed", "err", munErr)
			}

			for k, v := range kvSecret {
				outputSecret.Key = k
				outputSecret.Value = v
				logger.Debug("appending secret key-value pair", "key", k)
				outputPath.Kv_secrets = append(outputPath.Kv_secrets,
					outputSecret)
			}

			kvSecret = nil
		default:
			readsec, readerr := client.Logical().Read(sec2Path)
			if readerr != nil {
				logger.Error("cannot read v2 secret path", "path", sec2Path)
			}

			munErr := marshalUnmarshal(readsec.Data, &kv2Secret)
			if munErr != nil {
				logger.Error("json marshal/unmarshal failed", "err", munErr)
			}

			for k, v := range kv2Secret.Data {
				outputSecret.Key = k
				outputSecret.Value = v
				logger.Debug("appending secret key-value pair", "key", k)
				outputPath.Kv_secrets = append(outputPath.Kv_secrets,
					outputSecret)
			}

			kv2Secret.Data = nil
		}

		output.Paths = append(output.Paths, outputPath)
		outputPath.Path = ""
		outputPath.Kv_secrets = nil
	}

	return output
}

func dumpTransitMount(client *vault.Client, mount string) mountDump {
	var keysPath string
	var output mountDump
	var outputPath pathDump
	var keyBackup transitSecretDump

	var transitSecret struct {
		Keys []string `json:"keys"`
	}

	var transitKeyOptions struct {
		AllowBackup bool `json:"allow_plaintext_backup"`
	}

	logger.Debug("dumpTransitMount() called")

	output.Mount = mount
	output.Type = "transit"

	keysPath = fmt.Sprintf("%skeys", mount)

	transitKeys, tErr := client.Logical().List(keysPath)
	if tErr != nil {
		logger.Error("cannot list transit keys", "mount", mount, "err", tErr)
	} else {
		munErr := marshalUnmarshal(transitKeys.Data, &transitSecret)
		if munErr != nil {
			logger.Error("json marshal/unmarshal failed", "err", munErr)
		}

		for _, k := range transitSecret.Keys {
			outputPath.Path = k
			rkey := fmt.Sprintf("%skeys/%s", mount, k)
			bkey := fmt.Sprintf("%sbackup/%s", mount, k)
			readKey, rErr := client.Logical().Read(rkey)
			if rErr != nil {
				logger.Error("failed to read keys", "key", rkey, "err", rErr)
			}

			ukMunErr := marshalUnmarshal(readKey.Data, &transitKeyOptions)
			if ukMunErr != nil {
				logger.Error("json marshal/unmarshal failed", "err", ukMunErr)
			}

			if transitKeyOptions.AllowBackup {
				logger.Info("backing up transit key", "mount", mount, "key", k)
				backupKey, bErr := client.Logical().Read(bkey)
				if bErr != nil {
					logger.Error("failed to backup key", "key", k, "err", bErr)
				}

				bMunErr := marshalUnmarshal(backupKey.Data, &keyBackup)
				if bMunErr != nil {
					logger.Error("json marshal/unmarshal failed",
						"err", bMunErr)
				}

				outputPath.Transit_keys = keyBackup
			} else {
				logger.Warn("transit key is not allowed to backed up",
					"mount", mount, "key", k)
			}

			output.Paths = append(output.Paths, outputPath)
		}
	}

	return output
}

func dump() []byte {
	var dumpOut vaultDump
	logger.Debug("dump() called")

	client, err := authenticate()

	if err != nil {
		logger.Error("failed to start new client", "err", err)
		os.Exit(1)
	} else {
		logger.Info("connected to vault", "vaultAddr", vaultAddr)
	}

	logger.Debug("reading mounts")
	dumpOut.Address = vaultAddr
	dumpOut.Timestamp = time.Now().Unix()

	mounts, err := client.Sys().ListMounts()

	if err != nil {
		logger.Error("could not read mounts", "err", err)
		os.Exit(1)
	} else {
		for path, mount := range mounts {
			logger.Debug("mount found",
				"path", path,
				"type", mount.Type,
				"options", mount.Options)

			switch mount.Type {
			case "kv":
				logger.Info("performing kv dump", "path", path)
				dumpOut.Mounts = append(dumpOut.Mounts,
					dumpKvMount(client, path))
			case "transit":
				logger.Info("performing transit key dump", "path", path)
				dumpOut.Mounts = append(dumpOut.Mounts,
					dumpTransitMount(client, path))
			default:
				logger.Warn("mount type not supported",
					"mount.Type", mount.Type)
			}
		}
	}

	jsonOut, err := json.Marshal(dumpOut)
	if err != nil {
		logger.Error("cannot marshal vault dump", "err", err)
	}

	return jsonOut
}

func restoreKvPath(client *vault.Client, mount string, path string, secrets []kvSecretDump) {
	var v1payload = make(map[string]interface{})
	var v2payload = make(map[string]interface{})
	var kv2Payload = make(map[string]string)
	var reSearch *regexp.Regexp
	var reReplace string

	logger.Debug("restoreKvPath() called")

	for _, s := range secrets {
		v1payload[s.Key] = s.Value
		kv2Payload[s.Key] = s.Value
	}

	v2payload["data"] = kv2Payload

	_, wErr := client.Logical().Write(path, v1payload)
	if wErr != nil {
		logger.Debug("looks like this is a v2 secret", "err", wErr)
		reSearch = regexp.MustCompile(fmt.Sprintf("^(%s)", mount))
		reReplace = "${1}data/${2}"
		sec2Path := reSearch.ReplaceAllString(path, reReplace)
		logger.Debug("attempting to write to v2 path", "path", sec2Path)

		_, w2Err := client.Logical().Write(sec2Path, v2payload)
		if w2Err != nil {
			logger.Error("failed to restore secret",
				"path", path, "err", w2Err)
		} else {
			logger.Info("restored kv secret", "mount", mount,
				"path", path, "version", "v2")
		}
	} else {
		logger.Info("restored kv secret", "mount", mount,
			"path", path, "version", "v1")
	}
}

func restoreTransitKeys(client *vault.Client, mount string, path string, key transitSecretDump) {
	var payload = make(map[string]interface{})
	var keyPath string

	logger.Debug("restoreTransitKeys() called")

	payload["backup"] = key.Backup
	keyPath = fmt.Sprintf("%srestore/%s", mount, path)

	_, wErr := client.Logical().Write(keyPath, payload)
	if wErr != nil {
		logger.Error("failed to restore transit key",
			"path", keyPath, "err", wErr)
	} else {
		logger.Info("restored key", "mount", mount, "path", path)
	}
}

func restoreKvMount(client *vault.Client, mount string, paths []pathDump) {
	logger.Debug("restoreKvMount() called")

	for _, p := range paths {
		logger.Info("restoring secret path", "mount", mount, "path", p.Path)
		restoreKvPath(client, mount, p.Path, p.Kv_secrets)
	}
}

func restoreTransitMount(client *vault.Client, mount string, paths []pathDump) {
	logger.Debug("restoreTransitMount() called")

	for _, p := range paths {
		logger.Info("restoring secret path", "mount", mount, "path", p.Path)
		restoreTransitKeys(client, mount, p.Path, p.Transit_keys)
	}
}

func restore(dump []byte) {
	var mounts []string
	var dumpIn vaultDump

	logger.Debug("restore() called")
	logger.Debug("unmarshal of dump started")

	jsonErr := json.Unmarshal(dump, &dumpIn)
	if jsonErr != nil {
		logger.Error("failed to unmarshal dump", "err", jsonErr)
	}

	if (dumpIn.Address != eVaultAddr) && !ignoreAddress {
		logger.Error("VAULT_ADDR does not match address in dump file",
			"address", dumpIn.Address, "VAULT_ADDR", eVaultAddr)
		logger.Error("to continue use --ignore-address")
		os.Exit(1)
	}

	client, err := authenticate()
	if err != nil {
		logger.Error("failed to create vault client", "err", err)
	} else {
		logger.Info("connected to vault", "vaultAddr", vaultAddr)
	}

	client.SetToken(vaultToken)

	mountsList, err := client.Sys().ListMounts()
	mounts = make([]string, len(mountsList))
	if err != nil {
		logger.Error("could not list mounts", "err", err)
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
		logger.Debug("searching for mount", "mount", m.Mount,
			"found", mountExists)

		if mountExists {
			logger.Info("restoring mount point", "mount", m.Mount)
			switch m.Type {
			case "kv":
				logger.Debug("mount is a kv", "mount", m.Mount)
				restoreKvMount(client, m.Mount, m.Paths)
			case "transit":
				logger.Debug("mount is a transit", "mount", m.Mount)
				restoreTransitMount(client, m.Mount, m.Paths)
			default:
				logger.Warn("unsupported mount type", "type", m.Type)
			}
		} else {
			logger.Warn("could not find mount point", "mount", m.Mount)
		}
	}
}

func run() {
	var logLevel string

	if debug {
		logLevel = "DEBUG"
	} else {
		logLevel = "INFO"
	}

	logger = hclog.New(&hclog.LoggerOptions{
		Name:       "vault_dump",
		Level:      hclog.LevelFromString(logLevel),
		JSONFormat: logFmt,
		Color:      hclog.AutoColor,
	})

	if showVersion {
		logger.Info("created by Xan Manning",
			"version", version, "git-hash", gitHash)
		os.Exit(0)
	}

	logger.Debug("logger created")
	logger.Debug("run() called")

	if keyFile == "" {
		logger.Debug("empty key file path string", "keyFile", keyFile)
		logger.Error("--key needs and argument")
		os.Exit(1)
	}

	if action == "" {
		logger.Debug("empty action string", "action", action)
		logger.Error("--action needs and argument")

		os.Exit(1)
	} else {
		logger.Debug("action string defined", "action", action)

		switch action {
		case "dump":
			if outFile == "" {
				logger.Error("output file path required (--output|-o)")
				os.Exit(1)
			}

			logger.Info("dump has been requested", "file", outFile)

			keyRing = loadKey()
			jsonOut := dump()

			logger.Debug("starting encryption of json")

			out, err := keyRing.Encrypt(crypto.NewPlainMessage(jsonOut), nil)
			if err != nil {
				logger.Error("failed to encrypt dump output", "err", err)
				os.Exit(1)
			} else {
				logger.Info("encrypted json file with key", "key", keyFile)
			}

			output, err := out.GetArmored()
			if err != nil {
				logger.Error("failed to get armoured dump output", "err", err)
				os.Exit(1)
			}

			wOErr := ioutil.WriteFile(outFile, []byte(output), 0600)
			if wOErr != nil {
				logger.Error("failed to write output file", "file", outFile)
			} else {
				logger.Info("backup file written", "file", outFile)
			}
		case "restore":
			if inFile == "" {
				logger.Error("input file path required (--input|-i)")
				os.Exit(1)
			}

			logger.Info("restore has been requested", "file", inFile)

			keyRing = loadKey()

			encDump, err := ioutil.ReadFile(inFile)
			if err != nil {
				logger.Error("cannot read input file", "file",
					inFile, "err", err)
				os.Exit(1)
			} else {
				logger.Info("encrypted input file read", "file", inFile)
			}

			encMessage, err := crypto.NewPGPMessageFromArmored(string(encDump))
			if err != nil {
				logger.Error("failed to parse ciphertext", "err", err)
				os.Exit(1)
			}

			dumpContent, err := keyRing.Decrypt(encMessage, nil, 0)
			if err != nil {
				logger.Error("failed decrypting input dump file",
					"file", inFile, "err", err)
				os.Exit(1)
			} else {
				logger.Info("decrypted input dump file", "file", inFile)
			}

			restore([]byte(dumpContent.GetString()))
		default:
			logger.Error("unknown action has been requested", "action", action)
			os.Exit(1)
		}
	}

	logger.Debug("end of command")
}
