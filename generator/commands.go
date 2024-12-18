package main

import (
	"embed"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
)

type command struct {
	// function name this command refers to
	Name string
	// verb, i.e. the http operation
	Verb string
	// the Tessi entity that is being invoked
	Thing string
	// the Tessi security resource that is being used
	Resource string
	// an adverb used to separate functions for the same verb/thing
	Variant string
	// the first sentence or clause of the swagger documentation for this command
	Short string
	// the whole swagger documentation for this command
	Long string
	// a JSON string that defines how the data should be formatted
	Usage string
	// some other ways to call the command
	Aliases []string
}

// embed the swagger spec
//
//go:embed "tessitura api.15.2.40.json"
var api []byte

// just needed to keep embed in imports for the linter
var _ embed.FS

var swagger *spec.Swagger

// load the swagger spec
func init() {
	swagger = new(spec.Swagger)
	swagger.UnmarshalJSON(api)
	spec.ExpandSpec(swagger, nil)
}

// Reads the Tessitura swagger spec and extracts documentation info
func describe(funcName string) (thing string, long string, resource string) {

	// now find the corresponding operation in the swagger spec!
	for key, path := range swagger.Paths.Paths {
		for _, op := range []*spec.Operation{
			path.Get, path.Put, path.Post, path.Delete, path.Head,
		} {
			// funcName is often appended in golang by a suffix
			// (often `-fm` to make the name unique)
			// https://stackoverflow.com/questions/32925344/why-is-there-a-fm-suffix-when-getting-a-functions-name-in-go
			if op != nil && funcName ==
				// the swagger doc has an extra "_" in the name
				strings.ReplaceAll(op.ID, "_", "") {
				thing = regexp.MustCompile("_.+").ReplaceAllString(op.ID, "")

				long = op.Summary
				resource = regexp.MustCompile("/\\{.+\\}").ReplaceAllString(key, "")

				return
			}

		}
	}

	return
}

// Instantiate a struct type and fill it with descriptions up to depth (starting at 0)
func instantiateStructType(t reflect.Type, depth int) (s any, maxDepth int) {
	var v reflect.Value
	maxDepth = 0

	// instantiate the root element
	if t.Kind() == reflect.Pointer {
		// v = *new(*t)
		v = reflect.New(t.Elem()).Elem()
	} else {
		// v = *new(t)
		v = reflect.New(t).Elem()
	}

	// instantiate struct fields
	if v.Kind() == reflect.Struct {
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if field.CanSet() {
				if field.Kind() == reflect.Pointer {
					field.Set(reflect.New(field.Type().Elem()))
					field = field.Elem()
				}
				switch field.Kind() {
				case reflect.Bool:
					field.SetBool(true)
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
					reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					field.SetInt(123)
				case reflect.Float32, reflect.Float64:
					field.SetFloat(123.456)
				case reflect.String:
					field.SetString("string")
				case reflect.Slice, reflect.Struct:
					// recurse!
					if field.Kind() == reflect.Slice {
						field.Set(reflect.MakeSlice(field.Type(), 1, 1))
						field = field.Index(0)
					}
					if depth > 0 {
						if field.Type() != reflect.TypeOf(strfmt.DateTime{}) {
							s, i := instantiateStructType(field.Type(), depth-1)
							field.Set(reflect.ValueOf(s))
							maxDepth = max(maxDepth, i+1)
						} else {
							date, _ := strfmt.ParseDateTime("2000-01-01")
							field.Set(reflect.ValueOf(date))
						}
					} else {
						// unset pointer
						v.Field(i).SetZero()
					}
				}
			}
		}
	}

	if t.Kind() == reflect.Pointer {
		s = v.Addr().Interface()
	} else {
		s = v.Interface()
	}
	return
}

// Generate usage for `method` by instantiating its first (non-receiver) argument
// and marshaling it to a JSON byte string, removing go-swagger specific parts
func usage(method reflect.Method) string {
	numIn := method.Type.NumIn()
	if numIn < 2 {
		return ""
	}
	s, depth := instantiateStructType(method.Type.In(numIn-2), 2)
	params := reflect.ValueOf(s)
	if params.Kind() == reflect.Pointer {
		params = params.Elem()
	}
	if params.Kind() != reflect.Struct {
		// Oops! Don't know what to do =)
		return ""
	}

	// have to remove fields before marshaling because HTTPClient is a function
	paramsMap := make(map[string]any)
	removeFields := []string{"timeout", "Context", "HTTPClient"}
	for i := 0; i < params.NumField(); i++ {
		fieldName := params.Type().Field(i).Name
		if !slices.Contains(removeFields, fieldName) {
			paramsMap[fieldName] = params.Field(i).Interface()
		}
	}

	usageB, err := json.Marshal(paramsMap)
	usage := string(usageB)

	if err != nil {
		panic(err)
	}
	if string(usage) == "{}" {
		return ""
	}

	if depth > 1 {
		// simplify nested objects to just ids
		usage = regexp.
			MustCompile(`{[^{}]*("Id":[^,}]+)[^{}]*}`).
			ReplaceAllString(usage, `{$1}`)
	}
	// make a nice array notation
	usage = regexp.MustCompile(`]`).ReplaceAllString(usage, `,...]`)

	// remove outer nesting
	usage = regexp.MustCompile(`^({[^{]*)"[^"]+":{(.+)}([^}]*})$`).
		ReplaceAllString(usage, `$1$2$3`)

	// remove null values
	usage = strings.ReplaceAll(regexp.MustCompile(`,?"[^"]+":null`).
		ReplaceAllString(usage, ""), "{,", "{")

	// add some spacing
	usage = strings.ReplaceAll(usage, ",", ", ")

	// // fix case of duplicated keys
	// if strings.Contains(usage, `"ID":"string"`) {
	// 	usage = strings.ReplaceAll(usage, `"Id":123,`, "")
	// }
	return usage
}

// Fills a command struct with info about a method.
// Verb == {"Get", "Update", "Create", "Delete"}
// Thing, Long come from describe(method.Name)
// method.Name = Thing + Verb + Variant (in any order)
// Short is derived from Long by cutting at punctuation or newline.
// Usage comes from usage(method.Name)
func newCommand(method reflect.Method) command {
	thing, long, resource := describe(method.Name)
	stopWords := []string{"Get", "Update", "Create", "Delete", thing}
	variant := method.Name
	verb := ""
	for _, stopWord := range stopWords {
		if strings.Contains(variant, stopWord) && verb == "" {
			verb = stopWord
		}
		variant = strings.Replace(variant, stopWord, "", 1)
	}
	short := regexp.MustCompile(`[\.,\n]`).Split(long, 2)[0]
	return command{
		Name:     method.Name,
		Resource: resource,
		Verb:     verb,
		Thing:    thing,
		Short:    short,
		Variant:  variant,
		Long:     long,
		Usage:    usage(method),
		Aliases:  []string{short},
	}

}

// Generate aliases for CamelCased name -- one letter per capital plus the whole command
// both upper and lowercased... but not the same name back again
func makeAliases(name string) []string {
	substrings := map[string]bool{
		name: true, strings.ToLower(name): true,
	}
	caps := ""
	for i := 0; i < len(name); i++ {
		if string(name[i]) == strings.ToUpper(string(name[i])) {
			caps = caps + string(name[i])
		}
	}
	if caps != "" {
		substrings[caps] = true
		substrings[strings.ToLower(caps)] = true
	}
	delete(substrings, name)
	out := make([]string, 0, len(substrings))
	for key := range substrings {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}
