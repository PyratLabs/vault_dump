package kv

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/PyratLabs/vault_dump/core"

	vault "github.com/hashicorp/vault/api"
)

type KvSecretDump struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func CreateKVMount(client *vault.Client, mount string, version int, description string, config vault.MountConfigOutput, options map[string]string) {
	var configIn vault.MountInput
	var configStruct struct {
		Config vault.MountConfigInput `json:"config"`
	}

	if options == nil {
		options = make(map[string]string)
	}

	options["version"] = strconv.Itoa(version)

	configIn.Options = options
	configIn.Type = "kv"
	configIn.Description = description

	muErr := core.MarshalUnmarshal(config, &configStruct)
	if muErr != nil {
		core.Logger.Error("failed to marshal/unmarshal mount config",
			"err", muErr)
	}

	configIn.Config = configStruct.Config

	client.Sys().Mount(mount, &configIn)
}

func ListKvSecrets(client *vault.Client, mount string) []string {
	var keys *vault.Secret
	var kvPath string
	var kv2Path string
	var outPaths []string
	var pathCheck string
	var reSearch *regexp.Regexp
	var reReplace string
	var vPrefix string

	core.Logger.Debug("listKvSecrets() called")

	reSearch = regexp.MustCompile("^(.*?)/")
	reReplace = "${1}/metadata/$2"
	kvPath = mount
	kv2Path = reSearch.ReplaceAllString(mount, reReplace)

	var secretPaths struct {
		Paths []string `json:"keys"`
	}

	core.Logger.Debug("reading path", "kvPath", kvPath)
	kvkeys, kverr := client.Logical().List(kvPath)
	core.Logger.Debug("results found with v1 list",
		"results", len(kvkeys.Data))
	if kverr != nil {
		core.Logger.Error("could not list paths", "mount", mount, "err", kverr)
	}

	if len(kvkeys.Data) < 1 {
		core.Logger.Debug("could not find v1 secret, trying v2",
			"kv2Path", kv2Path)
		kv2keys, kv2err := client.Logical().List(kv2Path)
		if kv2err != nil {
			core.Logger.Error("count not list paths",
				"mount", mount, "err", kv2err)
		}
		keys = kv2keys
		vPrefix = "v2"
	} else {
		core.Logger.Debug("could not find v2 secret, trying v1",
			"kvPath", kvPath)
		keys = kvkeys
		vPrefix = "v1"
	}

	if keys != nil {
		munErr := core.MarshalUnmarshal(keys.Data, &secretPaths)
		if munErr != nil {
			core.Logger.Error("json marshal/unmarshal failed", "err", munErr)
		}

		for _, p := range secretPaths.Paths {
			pathCheck = p[len(p)-1:]
			newPath := fmt.Sprintf("%s%s", mount, p)
			returnPath := fmt.Sprintf("%s:%s", vPrefix, newPath)
			if pathCheck == "/" {
				core.Logger.Debug("path found", "path", p)
				outPaths = append(outPaths, ListKvSecrets(client, newPath)...)
				if outPaths == nil {
					core.Logger.Error("could not read path", "path", newPath)
				}

			} else {
				outPaths = append(outPaths, returnPath)
			}
		}
	}

	return outPaths
}

func DumpKvMount(client *vault.Client, mount string, config *vault.MountOutput) core.MountDump {
	var output core.MountDump
	var outputPath core.PathDump
	var outputSecret KvSecretDump
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

	core.Logger.Debug("dumpKvMount() called")

	output.Mount = mount
	output.Type = "kv"
	output.Options = config.Options
	output.Config = config.Config
	output.Description = config.Description

	secList = ListKvSecrets(client, mount)

	core.Logger.Debug("secrets list generated", "secList", secList)

	for _, sec := range secList {
		verSearch = regexp.MustCompile(":")
		verSplit = verSearch.Split(sec, 2)
		secVer = verSplit[0]
		secPath = verSplit[1]
		secSearch = regexp.MustCompile("^(.*?)/")
		secReplace = "${1}/data/${2}"
		sec2Path = secSearch.ReplaceAllString(verSplit[1], secReplace)

		core.Logger.Info("backing up kv path", "mount", mount,
			"path", secPath, "version", secVer)

		outputPath.Path = secPath

		switch secVer {
		case "v1":
			output.Version = 1

			readsec, readerr := client.Logical().Read(secPath)
			if readerr != nil {
				core.Logger.Error("cannot read v1 secret path",
					"path", secPath)
			}

			munErr := core.MarshalUnmarshal(readsec.Data, &kvSecret)
			if munErr != nil {
				core.Logger.Error("json marshal/unmarshal failed",
					"err", munErr)
			}

			for k, v := range kvSecret {
				outputSecret.Key = k
				outputSecret.Value = v
				core.Logger.Debug("appending secret key-value pair", "key", k)
				outputPath.Secrets = append(outputPath.Secrets,
					outputSecret)
			}

			kvSecret = nil
		default:
			output.Version = 2

			readsec, readerr := client.Logical().Read(sec2Path)
			if readerr != nil {
				core.Logger.Error("cannot read v2 secret path",
					"path", sec2Path)
			}

			munErr := core.MarshalUnmarshal(readsec.Data, &kv2Secret)
			if munErr != nil {
				core.Logger.Error("json marshal/unmarshal failed",
					"err", munErr)
			}

			for k, v := range kv2Secret.Data {
				outputSecret.Key = k
				outputSecret.Value = v
				core.Logger.Debug("appending secret key-value pair", "key", k)
				outputPath.Secrets = append(outputPath.Secrets,
					outputSecret)
			}

			kv2Secret.Data = nil
		}

		output.Paths = append(output.Paths, outputPath)
		outputPath.Path = ""
		outputPath.Secrets = nil
	}

	return output
}

func RestoreKvPath(client *vault.Client, mount string, path string, secrets []map[string]interface{}) {
	var v1payload = make(map[string]interface{})
	var v2payload = make(map[string]interface{})
	var kv2Payload = make(map[string]interface{})
	var reSearch *regexp.Regexp
	var reReplace string

	core.Logger.Debug("restoreKvPath() called")

	for _, s := range secrets {
		v1payload[s["key"].(string)] = s["value"].(string)
		kv2Payload[s["key"].(string)] = s["value"].(string)
	}

	v2payload["data"] = kv2Payload

	_, wErr := client.Logical().Write(path, v1payload)
	if wErr != nil {
		core.Logger.Debug("looks like this is a v2 secret", "err", wErr)
		reSearch = regexp.MustCompile(fmt.Sprintf("^(%s)", mount))
		reReplace = "${1}data/${2}"
		sec2Path := reSearch.ReplaceAllString(path, reReplace)
		core.Logger.Debug("attempting to write to v2 path", "path", sec2Path)

		_, w2Err := client.Logical().Write(sec2Path, v2payload)
		if w2Err != nil {
			core.Logger.Error("failed to restore secret",
				"path", path, "err", w2Err)
		} else {
			core.Logger.Info("restored kv secret", "mount", mount,
				"path", path, "version", "v2")
		}
	} else {
		core.Logger.Info("restored kv secret", "mount", mount,
			"path", path, "version", "v1")
	}
}

func RestoreKvMount(client *vault.Client, mount string, paths []core.PathDump) {
	core.Logger.Debug("restoreKvMount() called")
	var secrets []map[string]interface{}

	for _, p := range paths {
		core.Logger.Info("restoring secret path",
			"mount", mount, "path", p.Path)
		for _, s := range p.Secrets {
			secrets = append(secrets, s.(map[string]interface{}))
		}
		RestoreKvPath(client, mount, p.Path, secrets)

		secrets = nil
	}
}
