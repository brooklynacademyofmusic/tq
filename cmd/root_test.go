package cmd

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/skysyzygy/tq/tq"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var test_cmd = &cobra.Command{
	PreRunE: initTq,
	RunE: func(cmd *cobra.Command, args []string) error {
		input, _ := _tq.ReadInput()
		_tq.Log.Info(string(input))
		return fmt.Errorf("%s", string(input))
	},
}

// test that initLog sets up logging by creating a tq instance
func Test_initLog(t *testing.T) {
	logFile = os.TempDir() + string(os.PathSeparator) + "test.log"
	defer func() { logFile = "" }()

	initLog()
	_tq.Log.Info("Starting log!")

	// test that log file is getting written to
	assert.FileExists(t, logFile)
	log, _ := os.ReadFile(logFile)
	assert.Contains(t, string(log), "Starting log!")

	// test that unwriteable log file throws an error
	logFile = "not_a_dir/test.log"
	_, err := tq.CaptureOutput(func() {
		initLog()
	})
	assert.Regexp(t, "cannot open log file .+ for appending", string(err))
	logFile = ""
}

// test that log and file options are getting set for cobra commands by tqInit
func Test_tqInit(t *testing.T) {
	test_json := []byte(`{"some":"json"}`)

	os.WriteFile("test.json", test_json, 0644)
	defer os.Remove("test.json")

	viper.Set("file", "test.json")
	defer func() { viper.Set("file", "") }()

	viper.Set("log", os.TempDir()+string(os.PathSeparator)+"test.log")
	defer func() { viper.Set("log", "") }()

	viper.Set("login", authString)

	var err error
	// test that input file is getting read
	tq.CaptureOutput(func() {
		err = test_cmd.Execute()
	})
	assert.ErrorContains(t, err, string(test_json))

	// test that log file is getting written to
	assert.FileExists(t, logFile)
	log, _ := os.ReadFile(logFile)
	assert.Contains(t, string(log), "\\\"some\\\":\\\"json\\\"")
}

func Test_tqInit_Errors(t *testing.T) {
	viper.Set("file", "test.json")
	defer func() { viper.Set("file", "") }()

	viper.Set("login", authString)
	os.Remove(inFile)
	var err error

	// test that absent input file throws an error
	tq.CaptureOutput(func() {
		err = test_cmd.Execute()
	})
	assert.Regexp(t, "cannot open input file .* for reading", err.Error())
}

// Test that execute returns errors and output and handles compact flag
// but not when tq.OutFmt == "csv" (issue #25)
func Test_Execute(t *testing.T) {
	rootCmd.SetArgs(nil)
	stdout, _ := tq.CaptureOutput(Execute)

	assert.Contains(t, string(stdout), "Usage:")

	_tq.SetOutput([]byte(`{"test":"json"}`))
	defer func() { _tq.SetOutput(nil) }()
	stdout, _ = tq.CaptureOutput(Execute)

	assert.Regexp(t, regexp.MustCompile(`\{\n\s+"test":\s+"json"\n\}`), ansi.Strip(string(stdout)))

	compact = true
	defer func() { compact = false }()

	stdout, _ = tq.CaptureOutput(Execute)
	assert.Contains(t, ansi.Strip(string(stdout)), `{"test":"json"}`)

	_tq.OutFmt = "csv"
	defer func() { _tq.OutFmt = "json" }()
	compact = false
	_tq.SetOutput([]byte(`{"test":"json","test2":"csv"}`))
	stdout, _ = tq.CaptureOutput(Execute)
	assert.Contains(t, ansi.Strip(string(stdout)), "test,test2\n\"\"\"json\"\"\",\"\"\"csv\"\"\"")

}

// Test that help matches snapshots (regression testing)
func Test_Help(t *testing.T) {
	update := false

	rootCmd.SetArgs([]string{"help", "get", "constituents"})
	stdout, _ := tq.CaptureOutput(Execute)
	snaps.WithConfig(snaps.Filename("help_get_constituents"), snaps.Update(update)).MatchSnapshot(t, string(stdout))

	rootCmd.SetArgs([]string{"help", "create", "constituents"})
	stdout, _ = tq.CaptureOutput(Execute)
	snaps.WithConfig(snaps.Filename("help_create_constituents"), snaps.Update(update)).MatchSnapshot(t, string(stdout))

	viper.Set("inflat", true)
	stdout, _ = tq.CaptureOutput(Execute)
	fmt.Printf("_tq.InFlat: %v\nflatHelp: %v\nhighlight: %v\n", _tq.InFlat, *flatHelp, highlight)
	snaps.WithConfig(snaps.Filename("help_create_constituents_flat"), snaps.Update(update)).MatchSnapshot(t, string(stdout))

	viper.Set("highlight", true)
	viper.Set("inflat", false)
	defer func() { highlight = false }()
	stdout, _ = tq.CaptureOutput(Execute)
	fmt.Printf("_tq.InFlat: %v\nflatHelp: %v\nhighlight: %v\n", _tq.InFlat, *flatHelp, highlight)
	snaps.WithConfig(snaps.Filename("help_create_constituents_highlighted"), snaps.Update(update)).MatchSnapshot(t, string(stdout))
}
