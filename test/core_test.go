package main

import (
	"testing"

	"github.com/PyratLabs/vault_dump/core"
)

// func TestMarshalUnmarshal(t *testing.T) {
// 	var dataIn core.MountDump
// 	var dataOut struct {
// 		Mount       string `json:"mount"`
// 		Type        string `json:"type"`
// 		Version     int    `json:"version"`
// 		Description string `json:"description"`
// 	}

// 	dataIn.Mount = "test"
// 	dataIn.Type = "kv"
// 	dataIn.Version = 2
// 	dataIn.Description = "test data"

// 	err := core.MarshalUnmarshal(dataIn, &dataOut)
// 	if err != nil {
// 		t.Log("error, MarhsalUnmarshal should succeed.", err)
// 		t.Fail()
// 	}
// }

func TestLoadKey(t *testing.T) {
	core.KeyFile = append(core.KeyFile, "jsmith.pub")

	keyring := core.LoadKey()

	if !keyring.CanEncrypt() {
		t.Log("loaded public key cannot encrypt")
		t.Fail()
	}

	t.Log("Pass")
}

func TestTest(t *testing.T) {
	t.Log("Hello world")
	t.Fail()
}
