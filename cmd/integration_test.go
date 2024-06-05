package cmd

import (
	"io"
	"os"
	"testing"

	"github.com/skysyzygy/tq/tq"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func sendToStdin(query string) io.Reader {
	r, w, _ := os.Pipe()
	w.Write([]byte(query))
	w.Close()
	return r
}

// end-to-end get test
func Test_Get_Integration_empty(t *testing.T) {
	auth_string, _ := os.LookupEnv("AUTH_STRING")
	viper.Set("login", auth_string)
	var err error
	// test without payload
	rootCmd.SetIn(sendToStdin(""))
	rootCmd.SetArgs([]string{"get", "constituents"})
	tq.CaptureOutput(func() { err = rootCmd.Execute() })
	assert.ErrorContains(t, err, "500")
}

func Test_Get_Integration_invalid(t *testing.T) {
	var err error
	// test with invalid payload
	rootCmd.SetIn(sendToStdin(`{"constituentId":"0"}`))
	rootCmd.SetArgs([]string{"get", "constituents"})
	tq.CaptureOutput(func() { err = rootCmd.Execute() })
	assert.ErrorContains(t, err, "Constituent Id cannot be 0 or Null")
}

func Test_Get_Integration_valid(t *testing.T) {
	var err error
	// test with valid payload
	rootCmd.SetArgs([]string{"get", "constituents"})
	rootCmd.SetIn(sendToStdin(`{"constituentId":"1"}`))
	_, stderr := tq.CaptureOutput(func() { err = rootCmd.Execute() })
	assert.NoError(t, err)
	assert.Regexp(t, "Using config file: .+tq\n$", string(stderr))
	assert.Contains(t, string(_tq.GetOutput()), "Dummy")
}
