/*
Copyright © 2024 Sky Syzygy ssyzygy@bam.org

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/99designs/keyring"

	"github.com/skysyzygy/tq/auth"
	"github.com/skysyzygy/tq/tq"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	prettify "github.com/tidwall/pretty"
	"golang.org/x/term"
)

// Version number
const version string = "0.1.1"

var (
	cfgFile, inFile, logFile string
	verbose, pretty          bool
	_tq                      *tq.TqConfig
	keys                     auth.Keyring
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "tq",
	Short: "A toolkit for Tessitura",
	Long: helpParagraph("tq is a wrapper around the Tessitura API that reads " +
		"JSON-formatted data and outputs a series of API calls to Tessitura. " +
		"It internally handles authentication, session creation and " +
		"closure, and batch/concurrent processing so that humans like " +
		"you can focus on the data and not the intricacies of the API.\n\n" +
		"tq is basically a high-level API for common tasks in Tessi. "),
	Version: version,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	var out []byte
	if _tq != nil {
		out, err = _tq.GetOutput()
		if pretty {
			out = prettify.Pretty(out)
		}
		fmt.Println(jsonHighlight(string(out), false))
	}
	if err != nil {
		if _tq != nil && _tq.Log != nil {
			_tq.Log.Error(err.Error())
		} else {
			fmt.Println("Error: ", err.Error())
		}
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// enable case insensitive command names
	cobra.EnableCaseInsensitive = true
	// enable case insensitive flag names
	rootCmd.SetGlobalNormalizationFunc(func(f *pflag.FlagSet, name string) pflag.NormalizedName {
		return pflag.NormalizedName(strings.ToLower(name))
	})

	settings := make(map[string]string)
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
	}
	commit := strings.Join([]string{settings["vcs"], settings["vcs.revision"], settings["vcs.time"]}, " ")
	rootCmd.Version = rootCmd.Version + " (" + commit + ")"

	_tq = new(tq.TqConfig)

	//rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/.tq)")
	//handled early on for tq i/o initialization
	rootCmd.PersistentFlags().StringVarP(&inFile, "file", "f", "", "input file to read (default is to read from stdin)")
	rootCmd.PersistentFlags().StringVarP(&logFile, "log", "l", "", "log file to write to (default is no log)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "turns on additional diagnostic output")

	//used within tq for wrangling formats
	rootCmd.PersistentFlags().StringVarP(&_tq.InFmt, "in", "i", "json", "input format (csv or json; default is json); implies --inflat")
	rootCmd.PersistentFlags().StringVarP(&_tq.OutFmt, "out", "o", "json", "output format (csv or json; default is json); implies --outflat")
	rootCmd.PersistentFlags().BoolVar(&_tq.InFlat, "inflat", false, "use input flattened by JSONPath dot notation. Combining this with --help will show the flattened format")
	rootCmd.PersistentFlags().BoolVar(&_tq.OutFlat, "outflat", false, "use output flattened by JSONPath dot notation")
	rootCmd.PersistentFlags().BoolVarP(&_tq.DryRun, "dryrun", "n", false, "don't actually do anything, just show what would have happened")

	//used at output stage only
	rootCmd.PersistentFlags().BoolVarP(&pretty, "pretty", "p", false, "prettify the JSON output with indenting")

	// Hide global flags from auth command
	authenticateCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		authenticateCmd.InheritedFlags().VisitAll(func(f *pflag.Flag) { f.Hidden = true })
		return rootCmd.UsageFunc()(cmd)
	})

	width, _, err := term.GetSize(int(syscall.Stdout))
	if err != nil {
		width = 0
	}

	rootCmd.SetUsageTemplate(
		// Rename some things so that they align better with how they are used
		strings.NewReplacer("command", "verb", " Command", " Verb", "Examples", "Query",
			// Wrap flag usages and syntax highlight
			".FlagUsages", " | flagUsagesWrapped "+fmt.Sprint(width)+" (.Flag \"inflat\").Changed",
			// Indent example and syntax highlight
			".Example", ".Example | exampleWrapped "+fmt.Sprint(width)+" (.Flag \"inflat\").Changed").
			Replace(rootCmd.UsageTemplate()))

	cobra.AddTemplateFuncs(
		template.FuncMap{
			"flagUsagesWrapped": flagUsagesWrapped,
			"exampleWrapped":    exampleWrapped,
		})

	keys, _ = keyring.Open(keyring.Config{
		ServiceName: "tq",
	})

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".tq" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".tq")
		cfgFile = home + string(os.PathSeparator) + ".tq"
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	} else {
		cfg, err := os.OpenFile(cfgFile, os.O_CREATE|os.O_WRONLY, 0644)
		cfg.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Warning: couldn't access config file")
		}
	}

	initLog()
}

func initLog() {
	var log *os.File
	var err error
	if logFile != "" {
		// open log file for appending
		log, err = os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot open log file %v for appending.", logFile)
		}
	}
	_tq.SetLogger(log, verbose)
}

// Initializes a tq instance with input from file or stdin
// and logs it in using the default authentication method.
// Shouldn't be called until the last minute in order to make sure
// all flags are set and that we don't unnecessarily ping the server.
func initTq(cmd *cobra.Command, args []string) (err error) {
	var input io.Reader
	var _err error
	if inFile != "" {
		// open input file for reading
		input, _err = os.OpenFile(inFile, os.O_RDONLY, 0644)
		if _err != nil {
			err = errors.Join(fmt.Errorf("cannot open input file %v for reading", inFile), _err, err)
		}
	} else {
		input = cmd.InOrStdin()
	}

	a, _err := auth.FromString(viper.GetString("Login"))
	if _err != nil {
		err = errors.Join(fmt.Errorf("bad login string in config file"), _err, err)
	}

	err = errors.Join(a.Load(keys), err)

	if valid, _err := a.Validate(); !valid || _err != nil {
		err = errors.Join(fmt.Errorf("invalid login"), _err, err)
	}

	if err != nil {
		authString, _ := a.String()
		_tq.Log.Error(err.Error(),
			"logFile", logFile,
			"jsonFile", inFile,
			"auth", authString)
		return err
	}

	_tq.SetInput(input)
	return _tq.Login(a)
}
