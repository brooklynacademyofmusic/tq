package cmd

import (
	"os"
	"testing"

	"github.com/99designs/keyring"
	"github.com/skysyzygy/tq/auth"
	"github.com/skysyzygy/tq/tq"
	"github.com/stretchr/testify/assert"
)

// authFromInput gets auth data from the command line or env
func Test_authFromInput(t *testing.T) {
	initConfig()

	*hostname = "https://tessitura.api/basePath"
	*username = "user"
	*usergroup = "group"
	*location = "location"
	os.Setenv("TQ_LOGIN", "another/host|user|group|location")
	defer func() { os.Unsetenv("TQ_LOGIN") }()

	assert.Equal(t, auth.New(
		"https://tessitura.api/basePath", "user", "group", "location", nil),
		authFromInput())

	*hostname = ""
	*username = ""
	*usergroup = ""
	*location = ""
	assert.Equal(t, auth.New(
		"another/host", "user", "group", "location", nil),
		authFromInput())

}

// authenticateAddCmd adds an auth method
func Test_authenticateAddCmd(t *testing.T) {
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

	key, err := keys.Get("tessitura.api/basePath|user|group|location")
	assert.Error(t, err)

	authenticateAddCmd.RunE(authenticateAddCmd, nil)

	key, err = keys.Get("tessitura.api/basePath|user|group|location")
	assert.Equal(t, "tessitura.api/basePath|user|group|location", key.Key)
	assert.Equal(t, []byte("password"), key.Data)
	assert.NoError(t, err)

	r.Close()

	err = authenticateAddCmd.RunE(authenticateAddCmd, nil)
	assert.ErrorContains(t, err, "file already closed")

}

// authenticateListCmd lists all authentication methods
func Test_authenticateListCmd(t *testing.T) {
	*hostname = ""
	*username = ""
	*usergroup = ""
	*location = "not empty"

	stdout, stderr := tq.CaptureOutput(func() {
		authenticateListCmd.Run(authenticateListCmd, nil)
	})

	assert.Contains(t, string(stdout), "tessitura.api/basePath|user|group|location\n")
	assert.Contains(t, string(stderr), "Warning: parameters ignored")
}

func Test_authenticateSelectCmd(t *testing.T) {
	cfgFile = "tq.yaml"

	// root command calls this to read in the config file
	initConfig()

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
	defer func() { os.Remove("tq.yaml") }()
	cfgFile = "tq.yaml"
	// root command calls this to read in the config file
	initConfig()

	*hostname = "tessitura.api/basePath"
	*username = "user"
	*usergroup = "group"
	*location = "location"

	keys.Set(keyring.Item{Key: "tessitura.api/basePath|user|group|location"})

	authenticateSelectCmd.RunE(authenticateSelectCmd, nil)
	configFile, _ := os.ReadFile("tq.yaml")
	assert.Contains(t, string(configFile), "login: tessitura.api/basePath|user|group|location")
	assert.Contains(t, string(configFile), "verbose: true")
}

// authenticateDeleteCmd removes an authentication method
func Test_authenticateDeleteCmd(t *testing.T) {

	*hostname = "tessitura.api/basePath"
	*username = "user"
	*usergroup = "group"
	*location = "location"

	_, err := keys.Get("tessitura.api/basePath|user|group|location")
	assert.NoError(t, err)

	authenticateDeleteCmd.RunE(authenticateDeleteCmd, nil)

	_, err = keys.Get("tessitura.api/basePath|user|group|location")
	assert.Error(t, err)
}
