package transit

import (
	"fmt"

	"github.com/PyratLabs/vault_dump/core"
	vault "github.com/hashicorp/vault/api"
)

func DumpTransitMount(client *vault.Client, mount string) core.MountDump {
	var keysPath string
	var output core.MountDump
	var outputPath core.PathDump
	var keyBackup core.TransitSecretDump

	var transitSecret struct {
		Keys []string `json:"keys"`
	}

	var transitKeyOptions struct {
		AllowBackup bool `json:"allow_plaintext_backup"`
	}

	core.Logger.Debug("dumpTransitMount() called")

	output.Mount = mount
	output.Type = "transit"

	keysPath = fmt.Sprintf("%skeys", mount)

	transitKeys, tErr := client.Logical().List(keysPath)
	if tErr != nil {
		core.Logger.Error("cannot list transit keys", "mount", mount, "err", tErr)
	} else {
		munErr := core.MarshalUnmarshal(transitKeys.Data, &transitSecret)
		if munErr != nil {
			core.Logger.Error("json marshal/unmarshal failed", "err", munErr)
		}

		for _, k := range transitSecret.Keys {
			outputPath.Path = k
			rkey := fmt.Sprintf("%skeys/%s", mount, k)
			bkey := fmt.Sprintf("%sbackup/%s", mount, k)
			readKey, rErr := client.Logical().Read(rkey)
			if rErr != nil {
				core.Logger.Error("failed to read keys", "key", rkey, "err", rErr)
			}

			ukMunErr := core.MarshalUnmarshal(readKey.Data, &transitKeyOptions)
			if ukMunErr != nil {
				core.Logger.Error("json marshal/unmarshal failed", "err", ukMunErr)
			}

			if transitKeyOptions.AllowBackup {
				core.Logger.Info("backing up transit key", "mount", mount, "key", k)
				backupKey, bErr := client.Logical().Read(bkey)
				if bErr != nil {
					core.Logger.Error("failed to backup key", "key", k, "err", bErr)
				}

				bMunErr := core.MarshalUnmarshal(backupKey.Data, &keyBackup)
				if bMunErr != nil {
					core.Logger.Error("json marshal/unmarshal failed",
						"err", bMunErr)
				}

				outputPath.Transit_keys = keyBackup
			} else {
				core.Logger.Warn("transit key is not allowed to backed up",
					"mount", mount, "key", k)
			}

			output.Paths = append(output.Paths, outputPath)
		}
	}

	return output
}

func RestoreTransitKeys(client *vault.Client, mount string, path string, key core.TransitSecretDump) {
	var payload = make(map[string]interface{})
	var keyPath string

	core.Logger.Debug("restoreTransitKeys() called")

	payload["backup"] = key.Backup
	keyPath = fmt.Sprintf("%srestore/%s", mount, path)

	_, wErr := client.Logical().Write(keyPath, payload)
	if wErr != nil {
		core.Logger.Error("failed to restore transit key",
			"path", keyPath, "err", wErr)
	} else {
		core.Logger.Info("restored key", "mount", mount, "path", path)
	}
}

func RestoreTransitMount(client *vault.Client, mount string, paths []core.PathDump) {
	core.Logger.Debug("restoreTransitMount() called")

	for _, p := range paths {
		core.Logger.Info("restoring secret path", "mount", mount, "path", p.Path)
		RestoreTransitKeys(client, mount, p.Path, p.Transit_keys)
	}
}
