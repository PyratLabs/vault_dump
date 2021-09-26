package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/mitchellh/go-homedir"

	vault "github.com/hashicorp/vault/api"
)

var (
	EPassPhrase string = os.Getenv("VAULT_DUMP_PASSPHRASE")
	EVaultAddr  string = os.Getenv("VAULT_ADDR")
	EVaultToken string = os.Getenv("VAULT_TOKEN")

	Debug         bool
	IgnoreAddress bool
	InFile        string
	IsRestore     bool = false
	KeyFile       []string
	KeyRing       crypto.KeyRing
	KeyPass       string
	LogFmt        bool
	Logger        hclog.Logger
	OutFile       string
	VaultAddr     string
	VaultToken    string
)

type KvSecretDump struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type TransitSecretDump struct {
	Backup string `json:"backup"`
}

type PathDump struct {
	Path         string            `json:"path"`
	Kv_secrets   []KvSecretDump    `json:"kv_secrets"`
	Transit_keys TransitSecretDump `json:"transit_keys"`
}

type MountDump struct {
	Mount string     `json:"mount"`
	Type  string     `json:"type"`
	Paths []PathDump `json:"paths"`
}

type VaultDump struct {
	Timestamp int64       `json:"timestamp"`
	Address   string      `json:"address"`
	Mounts    []MountDump `json:"mounts"`
}

func MarshalUnmarshal(data interface{}, structure interface{}) error {
	var emptyErr error
	Logger.Debug("marshalUnmarshal() called")

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

func LoadKey() crypto.KeyRing {
	var keyObjUnlocked *crypto.Key

	Logger.Debug("loadKey() called")
	Logger.Debug("loading key file")

	if KeyPass == "" && EPassPhrase != "" {
		KeyPass = EPassPhrase
	}

	KeyRing, err := crypto.NewKeyRing(nil)
	if err != nil {
		Logger.Error("cannot create key ring", "err", err)
		os.Exit(1)
	}

	for _, keyfile := range KeyFile {
		raw_key, err := ioutil.ReadFile(keyfile)
		if err != nil {
			Logger.Error("unable to read file", "key", keyfile, "err", err)
			os.Exit(1)
		}

		keyObj, err := crypto.NewKeyFromArmored(string(raw_key))
		if err != nil {
			Logger.Error("unable to read key", "key", keyfile, "err", err)
			os.Exit(1)
		}

		if keyObj.IsPrivate() {
			Logger.Debug("private key loaded: can encrypt and decrypt")
			isLocked, err := keyObj.IsLocked()
			if err != nil {
				Logger.Error("unable to determine if key is locked", "err", err)
				os.Exit(1)
			}

			if isLocked {
				Logger.Debug("key information", "locked", "true")

				if KeyPass == "" {
					Logger.Error("cannot unlock key," +
						"no passphrase specified" +
						"(--passphrase|-p|VAULT_DUMP_PASSPHRASE)")
					os.Exit(1)
				}

				keyObjUnlocked, err = keyObj.Unlock([]byte(KeyPass))
				if err != nil {
					Logger.Error("unable to unlock key", "err", err)
					os.Exit(1)
				}

				Logger.Debug("key unlocked")
			} else {
				keyObjUnlocked = keyObj
			}
		} else {
			Logger.Debug("public key loaded: can encrypt only")
			Logger.Debug("is this a restore?", "IsRestore", IsRestore)
			if IsRestore {
				Logger.Error("key file is a public key, cannot decrypt vault dump",
					"KeyFile", KeyFile)
				os.Exit(1)
			}
			keyObjUnlocked = keyObj
		}

		if keyObjUnlocked.IsExpired() {
			Logger.Warn("key has expired")
		}

		Logger.Debug("key information", "fingerprint",
			keyObjUnlocked.GetFingerprint())
		Logger.Debug("key information", "id",
			keyObjUnlocked.GetKeyID())
		Logger.Debug("key information", "hex",
			keyObjUnlocked.GetHexKeyID())

		KeyRing.AddKey(keyObjUnlocked)
	}

	return *KeyRing
}

func Authenticate() (*vault.Client, error) {
	Logger.Debug("authenticate() called")

	if EVaultAddr != "" {
		VaultAddr = EVaultAddr
		Logger.Debug("VAULT_ADDR defined", "VaultAddr", VaultAddr)
	} else {
		VaultAddr = "http://localhost:8200"
		Logger.Debug("VAULT_ADDR undefined, using default",
			"VaultAddr", VaultAddr)
	}

	if EVaultToken != "" {
		VaultToken = EVaultToken
		Logger.Debug("VAULT_TOKEN defined", "VaultToken", VaultToken)
	} else {
		home, err := homedir.Dir()

		if err != nil {
			Logger.Warn("cannot determine home directory")
		}

		fileToken, err := ioutil.ReadFile(
			fmt.Sprintf("%s/.vault-token", home))

		if err != nil {
			Logger.Warn("failed to open token file", "err", err)
		} else {
			VaultToken = string(fileToken)
		}
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	Logger.Debug("creating vault client",
		"VaultAddr", VaultAddr, "VaultToken", VaultToken)

	client, err := vault.NewClient(&vault.Config{
		Address:    VaultAddr,
		HttpClient: httpClient,
	})

	client.SetToken(VaultToken)

	return client, err
}

func CreateLogger(name string, debug bool, json bool) hclog.Logger {
	var logLevel string

	if debug {
		logLevel = "DEBUG"
	} else {
		logLevel = "INFO"
	}

	return hclog.New(&hclog.LoggerOptions{
		Name:       name,
		Level:      hclog.LevelFromString(logLevel),
		JSONFormat: json,
		Color:      hclog.AutoColor,
	})
}
