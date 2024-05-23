package main

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"text/template"

	"github.com/skysyzygy/tq/client"
)

func main() {
	// add a new function to the template engine
	funcs := template.FuncMap{"join": strings.Join}
	templ, err := template.New("commands").Funcs(funcs).ParseFiles("commands.go.tmpl", "commands_test.go.tmpl")
	if err != nil {
		panic(err)
	}

	for _, op := range []string{"Get", "Put", "Post"} {
		data := getDataForOperation(op)
		file, err := os.Create("../cmd/" + strings.ToLower(op) + ".go")
		if err := errors.Join(templ.ExecuteTemplate(file, "commands.go.tmpl", data), err); err != nil {
			panic(err)
		}
		file, err = os.Create("../cmd/" + strings.ToLower(op) + "_test.go")
		if err := errors.Join(templ.ExecuteTemplate(file, "commands_test.go.tmpl", data), err); err != nil {
			panic(err)
		}
	}
}

// Run the template in `inFilename` using `data` and save as `outFilename`
func execTemplate(inFilename string, outFilename string, data any) error {
	tmpl, err := template.ParseFiles(inFilename)
	if err != nil {
		return err
	}
	outFile, err := os.Create(outFilename)
	if err != nil {
		return err
	}
	err = tmpl.Execute(outFile, data)
	if err != nil {
		return err
	}
	return outFile.Close()
}

// Build data about entities that can be used with `operation` (i.e. "Get", "Post", "Put")
func getDataForOperation(operation string) (data map[string]any) {
	client := client.New(nil, nil)
	doer, ok := reflect.TypeOf(*client).FieldByName(operation)
	if !ok {
		panic(fmt.Errorf("couldn't get client.%v", operation))
	}

	// Group commands by the thing they operate on
	commands := make(map[string][]command)
	for i := 0; i < doer.Type.NumMethod(); i++ {
		command := newCommand(doer.Type.Method(i))
		if command.Thing != "" {
			commands[command.Thing] = append(commands[command.Thing], command)
		}
	}

	// Ensure that the first command is the one without a variant
	for _, commands := range commands {
		slices.SortFunc(commands, func(a command, b command) int {
			return strings.Compare(a.Variant, b.Variant)
		})
	}

	data = make(map[string]any)
	data["op"] = operation
	data["commands"] = commands
	data["makeAliases"] = makeAliases
	return
}
