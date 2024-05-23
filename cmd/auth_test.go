package cmd

import (
	"os"
	"testing"

	"github.com/skysyzygy/tq/auth"

	"github.com/skysyzygy/tq/tq"
	"github.com/stretchr/testify/assert"
)

var skipAuth bool = false

// authenticateAddCmd adds an auth method
func Test_authenticateAddCmd(t *testing.T) {
	if skipAuth {
		t.Skip()
	}
	// test that the https gets removed
	*hostname = "https://tessitura.api/basePath"
	*username = "user"
	*usergroup = "group"
	*location = "location"
	password := []byte("password")

	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Write(password)
	w.Close()

	key, err := auth.Keys.Get("tessitura.api/basePath|user|group|location")
	assert.Error(t, err)

	authenticateAddCmd.RunE(authenticateAddCmd, nil)

	key, err = auth.Keys.Get("tessitura.api/basePath|user|group|location")
	assert.Equal(t, "tessitura.api/basePath|user|group|location", key.Key)
	assert.Equal(t, []byte("password"), key.Data)
	assert.NoError(t, err)

	r.Close()

	err = authenticateAddCmd.RunE(authenticateAddCmd, nil)
	assert.ErrorContains(t, err, "file already closed")

}

// authenticateListCmd lists all authentication methods
func Test_authenticateListCmd(t *testing.T) {
	if skipAuth {
		t.Skip()
	}

	*hostname = ""
	*username = ""
	*usergroup = ""
	*location = "not empty"

	stdout, stderr := tq.CaptureOutput(func() {
		authenticateListCmd.Run(authenticateListCmd, nil)
	})

	assert.Contains(t, string(stdout), "{tessitura.api/basePath user group location }")
	assert.Contains(t, string(stderr), "Warning: parameters ignored")
}

func Test_authenticateSelectCmd(t *testing.T) {
	cfgFile = "tq.yaml"
	assert.NoFileExists(t, "tq.yaml")

	// root command calls this to read in the config file
	initConfig()
	defer os.Remove("tq.yaml")

	*hostname = "tessitura.api/basePath"
	*username = "not_a_user"
	*usergroup = "group"
	*location = "location"

	err := authenticateSelectCmd.RunE(authenticateSelectCmd, nil)
	assert.ErrorContains(t, err, "The specified item could not be found in the keyring")

	*hostname = "tessitura.api/basePath"
	*username = "user"
	*usergroup = "group"
	*location = "location"

	err = authenticateSelectCmd.RunE(authenticateSelectCmd, nil)
	assert.NoError(t, err)

	configFile, _ := os.ReadFile("tq.yaml")
	assert.Contains(t, string(configFile), "login: tessitura.api/basePath|user|group|location")
}

func Test_authenticateSelectCmd_ExistingFile(t *testing.T) {
	os.WriteFile("tq.yaml", []byte("verbose: true\nlogin: null"), 0644)
	cfgFile = "tq.yaml"
	// root command calls this to read in the config file
	initConfig()
	defer os.Remove("tq.yaml")

	*hostname = "tessitura.api/basePath"
	*username = "user"
	*usergroup = "group"
	*location = "location"

	authenticateSelectCmd.RunE(authenticateSelectCmd, nil)
	configFile, _ := os.ReadFile("tq.yaml")
	assert.Contains(t, string(configFile), "login: tessitura.api/basePath|user|group|location")
	assert.Contains(t, string(configFile), "verbose: true")
}

// authenticateDeleteCmd removes an authentication method
func Test_authenticateDeleteCmd(t *testing.T) {
	if skipAuth {
		t.Skip()
	}

	*hostname = "tessitura.api/basePath"
	*username = "user"
	*usergroup = "group"
	*location = "location"

	_, err := auth.Keys.Get("tessitura.api/basePath|user|group|location")
	assert.NoError(t, err)

	authenticateDeleteCmd.RunE(authenticateDeleteCmd, nil)

	_, err = auth.Keys.Get("tessitura.api/basePath|user|group|location")
	assert.Error(t, err)
}