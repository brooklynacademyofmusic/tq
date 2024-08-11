// Generates the tq commands that integrate with the tessitura swagger API code generated by the code in ./swagger
//go:generate go run . cmd
//go:generate go run . test
//go:generate go run . docs

package main

import (
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"text/template"

	"github.com/skysyzygy/tq/client"
	"github.com/skysyzygy/tq/tq"
	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Short: "Tool to generate code and documentation for tq",
}

var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Generate mkdocs documentation",
	Run: func(cmd *cobra.Command, args []string) {
		templateData := make(map[string]any)
		templateData["commands"] = getCommandData()
		for _, op := range []string{"Get", "Post", "Put"} {
			templateData["op"] = op
			generate("docs_verbs.tmpl",
				"../doc/docs/"+strings.ToLower(op)+".md",
				templateData)
		}
		generate("docs_objects.tmpl", "../doc/docs/objects.md", templateData)
	},
}
var cmdCmd = &cobra.Command{
	Use:   "cmd",
	Short: "Generate go code in /cmd",
	Run: func(cmd *cobra.Command, args []string) {
		templateData := make(map[string]any)
		templateData["commands"] = getCommandData()
		for _, op := range []string{"Get", "Post", "Put"} {
			templateData["op"] = op
			generate("commands.go.tmpl",
				"../cmd/"+strings.ToLower(op)+".go",
				templateData)
		}
	},
}
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Generate go tests in /cmd",
	Run: func(cmd *cobra.Command, args []string) {
		templateData := make(map[string]any)
		templateData["commands"] = getCommandData()
		for _, op := range []string{"Get", "Post", "Put"} {
			templateData["op"] = op
			generate("commands_test.go.tmpl",
				"../cmd/"+strings.ToLower(op)+"_test.go",
				templateData)
		}
	},
}

func main() {
	err := generateCmd.Execute()
	if err != nil {
		panic(err)
	}
}

func init() {
	generateCmd.AddCommand(docsCmd, testCmd, cmdCmd)
}

func generate(templateFile string, outFile string, data map[string]any) {
	// add a new function to the template engine
	_tq := tq.TqConfig{}

	funcs := template.FuncMap{
		"join":    strings.Join,
		"left":    func(s string) string { return string(s[0]) },
		"toLower": strings.ToLower,
		"toFlat": func(s string) string {
			_tq.OutFlat = true
			_tq.OutFmt = "json"
			_tq.SetOutput([]byte(s))
			o, _ := _tq.GetOutput()
			return string(o)
		},
		"toCsv": func(s string) string {
			_tq.OutFlat = true
			_tq.OutFmt = "csv"
			_tq.SetOutput([]byte(s))
			o, _ := _tq.GetOutput()
			return string(o)

		},
	}
	templ, err := template.New("commands").Funcs(funcs).ParseFiles(templateFile, "docs_code.tmpl")
	if err != nil {
		panic(err)
	}

	file, err := os.Create(outFile)
	if err := errors.Join(templ.ExecuteTemplate(file, templateFile, data), err); err != nil {
		panic(err)
	}

}

// Build data about entities that can be used with `operation` (i.e. "Get", "Post", "Put")
func getCommandData() (data map[string]map[string][]command) {
	data = make(map[string]map[string][]command)
	client := client.New(nil, nil)
	clientType := reflect.TypeOf(*client)
	for i := 0; i < clientType.NumField(); i++ {
		doer := clientType.Field(i)
		// Group commands by the thing they operate on
		for i := 0; i < doer.Type.NumMethod(); i++ {
			cmd := newCommand(doer.Type.Method(i))
			if cmd.Thing != "" {
				if data[cmd.Thing] == nil {
					data[cmd.Thing] = make(map[string][]command)
				}
				data[cmd.Thing][doer.Name] = append(
					data[cmd.Thing][doer.Name], cmd)
			}
		}

		// Ensure that the first command is the one without a variant
		for _, commands := range data {
			slices.SortFunc(commands[doer.Name], func(a command, b command) int {
				return strings.Compare(a.Variant, b.Variant)
			})
		}
	}
	return
}
