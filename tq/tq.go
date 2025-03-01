package tq

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	run "runtime"
	"slices"
	"strings"
	"sync"

	"encoding/csv"
	"encoding/json"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/skysyzygy/tq/auth"
	"github.com/skysyzygy/tq/client"
)

// import "github.com/skysyzygy/tq/cmd"

// Global config options and structures for tq
type TqConfig struct {
	// the Tessitura API client
	*client.TessituraServiceWeb

	// Additional headers to add to requests, consumed by apiAuth
	Headers map[string]string

	// TODO: Bearer token for requests
	// tokenAuth func(*runtime.ClientOperation)

	// Logger, exported so that logging can happen from within the
	// command scripts
	Log *slog.Logger

	// some flags, set by New
	verbose, DryRun, InFlat, OutFlat bool
	InFmt, OutFmt                    string

	// input / output
	input  io.Reader
	output []byte
}

func (tq *TqConfig) SetLogger(logFile *os.File, verbose bool) {
	logLevel := new(slog.LevelVar)
	if verbose {
		logLevel.Set(slog.LevelInfo)
	} else {
		logLevel.Set(slog.LevelWarn)
	}
	tq.Log = slog.New(NewLogHandler(logFile, logLevel))
	tq.verbose = verbose
}

func (tq *TqConfig) SetInput(input io.Reader) { tq.input = input }
func (tq *TqConfig) ReadInput() (in []byte, err error) {
	var m []jsonMap
	if tq.InFmt == "csv" {
		c, err := csv.NewReader(tq.input).ReadAll()
		if err != nil {
			return nil, err
		}
		m, err = jsonMapsFromRecords(c)
		if err != nil {
			return nil, err
		}
	} else {
		in, err = io.ReadAll(tq.input)
		if err != nil {
			return nil, err
		}
	}
	if tq.InFlat || tq.InFmt == "csv" {
		if m == nil {
			m, err = jsonToJSONMaps(in)
		}
		if err != nil {
			return nil, err
		}
		in, err = unflattenJSONMaps(m)
	}
	return
}
func (tq TqConfig) GetOutput() (out []byte, err error) {
	var m []jsonMap
	if tq.OutFlat || tq.OutFmt == "csv" {
		m, err = flattenJSONMaps(tq.output)
		if err != nil {
			return nil, err
		}
	}
	if tq.OutFmt == "csv" {
		c := jsonMapsToRecords(m)
		w := bytes.NewBuffer(out)
		err = csv.NewWriter(w).WriteAll(c)
		if err != nil {
			return nil, err
		}
		out, err = io.ReadAll(w)
	} else {
		if m != nil {
			out, err = json.Marshal(m)
		} else {
			out = tq.output
		}
	}

	return
}

// For testing only
func (tq *TqConfig) SetOutput(test []byte) { tq.output = test }

// Prepare the Tessitura client with the given authentication info
func (tq *TqConfig) Authenticate(a auth.Auth) error {

	var clientAuths []runtime.ClientAuthInfoWriter

	if basicAuth, err := a.BasicAuth(); err != nil {
		tq.Log.Error(err.Error())
		return err
	} else {
		clientAuths = append(clientAuths, basicAuth)
	}

	if len(tq.Headers) > 0 {
		for k, v := range tq.Headers {
			clientAuths = append(clientAuths, httptransport.APIKeyAuth(k, "header", v))
		}
	}

	host := append(strings.SplitN(a.Hostname(), "/", 2), "")
	ignoreCerts, err := httptransport.TLSClient(httptransport.TLSClientOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}
	transport := httptransport.NewWithClient(host[0], host[1], []string{"https"}, ignoreCerts)
	transport.DefaultAuthentication = httptransport.Compose(clientAuths...)
	tq.TessituraServiceWeb = client.New(transport, nil)

	// if valid, err := a.Validate(tq.TessituraServiceWeb); !valid || err != nil {
	// 	return errors.Join(fmt.Errorf("invalid login"), err)
	// }

	return nil
}

// Generic for doing operations (get/put/post), parallelizing calls to DoOne as needed
// Returns the result, either a single json map if there is only one operation to do,
// or an array of json maps if there are multiple operations.
// Returns the last error
func Do[P any, R any, O any, F func(*P, ...O) (*R, error)](
	tq *TqConfig, function F,
) (err error) {
	tq.Log.Info(fmt.Sprint("calling swagger function: ",
		run.FuncForPC(reflect.ValueOf(function).Pointer()).Name()))
	tq.Log.Info("reading from input")
	query, err := tq.ReadInput()
	if err != nil {
		tq.Log.Error("error reading from input")
		return err
	}
	if len(query) == 0 {
		tq.Log.Info("query is empty, calling API endpoint once")
		tq.output, err = DoOne(*tq, function, query)
		return err
	}
	queries := new([]json.RawMessage)
	err = json.Unmarshal(query, queries)
	if _, ok := err.(*json.UnmarshalTypeError); ok {
		tq.Log.Info("query is not an array, calling API endpoint once")
		// it's not an array... so just call DoOne
		tq.output, err = DoOne(*tq, function, query)
		return err
	} else if err == nil {
		tq.Log.Info("query is an array, calling API endpoint multiple times")
		// loop over queries and call DoOne for each
		out := make([]json.RawMessage, len(*queries))
		errs := make([]error, len(*queries))
		wait := new(sync.WaitGroup)
		wait.Add(len(*queries))
		for i, q := range *queries {
			go func(i int, q json.RawMessage) {
				out[i], errs[i] = DoOne(*tq, function, q)
				wait.Done()
			}(i, q)
		}
		wait.Wait()
		errs = slices.DeleteFunc(errs, func(e error) bool { return e == nil })
		tq.output, _ = json.Marshal(out)
		if len(errs) > 0 {
			err = errs[len(errs)-1]
		}
		return err
	}
	return err // json.Unmarshal error
}

// Generic for doing operations (get/put/post), parallelizing calls to DoOne as needed
// The type parameters allow it to work for any swagger-defined function.
// It unmarshals `query` into the appropriate data structure for `function` and marshals
// the result back to json.
// If the initial unmarshal fails, it tries again with a depth-first traversal of the
// data structure, essentially trying to recast a flat query into the nested structure
// required.
func DoOne[P any, R any, O any, F func(*P, ...O) (*R, error)](
	tq TqConfig, function F, query []byte,
) ([]byte, error) {

	var err error
	var remainder map[string]any
	params := new(P)

	if len(query) > 0 {
		remainder, err = unmarshallStructWithRemainder(query, params)

		// If there are fields left over...
		if len(remainder) > 0 {
			remainder, err = unmarshallNestedStructWithRemainder(query, params,
				[]string{"timeout", "Context", "HTTPClient"})
		}

		if tq.verbose {
			tq.Log.Info("query fields mapped:", "fields", fmt.Sprint(structFields(*params)))
			tq.Log.Info("query fields ignored:", "fields", fmt.Sprint(mapFields(remainder)))
			if err != nil {
				tq.Log.Info("unmarshalling returned error:", "error", err)
			}
		}
	}

	if len(structFields(*params)) == 0 && len(remainder) > 0 {
		if tq.verbose {
			err = errors.Join(fmt.Errorf("query %v could not be parsed into %#v",
				string(query),
				params), err)
		} else {
			err = errors.Join(fmt.Errorf("query could not be parsed"), err)
		}
	}
	if tq.DryRun || err != nil {
		return nil, err
	}

	// Call the function
	obj, err := function(params)

	if err != nil {
		return nil, err
	} else {
		// Marshall the json response
		if !reflect.ValueOf(obj).Elem().IsZero() &&
			!reflect.ValueOf(obj).Elem().FieldByName("Payload").IsZero() {
			return json.Marshal(reflect.ValueOf(obj).Elem().FieldByName("Payload").Interface())
		} else {
			return json.Marshal(obj)
		}
	}
}

// Unmarshall into a struct and return the remainder as a map
// Errors if P is not a struct type
func unmarshallStructWithRemainder(query []byte, params any) (res map[string]any, err error) {
	if reflect.TypeOf(params).Kind() != reflect.Pointer {
		return nil, fmt.Errorf("params must be pointer to struct, got %v", reflect.TypeOf(params).Kind())
	} else if reflect.TypeOf(params).Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("params must be pointer to struct, got pointer to %v", reflect.TypeOf(params).Elem().Kind())
	}

	// Unmarshal the query into the given parameter structure
	_err := json.Unmarshal(query, params)
	err = errors.Join(err, _err)

	// Get all the keys of the query for comparison
	_err = json.Unmarshal(query, &res)
	err = errors.Join(err, _err)

	// Remove keys that are in the struct already
	typ := reflect.TypeOf(params).Elem()
	for key := range res {
		for i := 0; i < typ.NumField(); i++ {
			if key == typ.Field(i).Name ||
				key == strings.Split(typ.Field(i).Tag.Get("json"), ",")[0] {
				// But only if they are set
				field := reflect.ValueOf(params).Elem().Field(i)
				if !(field.IsZero() || field.Kind() == reflect.Pointer &&
					field.Elem().IsZero()) {
					delete(res, key)
				}
			}
		}
	}

	return
}

// Unmarshall into a nested struct from a flat query and return the remainder as a map
// Errors if P is not a struct type
func unmarshallNestedStructWithRemainder(query []byte, params any, except []string) (res map[string]any, err error) {
	if reflect.TypeOf(params).Kind() != reflect.Pointer {
		return nil, fmt.Errorf("params must be pointer to struct, got %v", reflect.TypeOf(params).Kind())
	} else if reflect.TypeOf(params).Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("params must be pointer to struct, got pointer to %v", reflect.TypeOf(params).Elem().Kind())
	}

	// First unmarshal the given struct so that those fields get mapped if possible
	res, err = unmarshallStructWithRemainder(query, params)

	query, _ = json.Marshal(res)
	if string(query) == "{}" {
		return
	}

	v := reflect.ValueOf(params).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		// Don't overwrite existing fields or `except`ed fields
		if (field.IsZero() || field.Kind() == reflect.Pointer &&
			field.Elem().IsZero()) && !slices.Contains(except, v.Type().Field(i).Name) {
			if field.Type().Kind() == reflect.Pointer {
				// new struct if pointer is nil
				field.Set(reflect.New(field.Type().Elem()))
			} else {
				field = field.Addr()
			}
			if field.Type().Elem().Kind() == reflect.Struct &&
				field.Type().Elem() != reflect.TypeOf(strfmt.DateTime{}) {
				// recurse if there's a struct field
				res, err = unmarshallStructWithRemainder(query, field.Interface())
				// Update the query with only unmatched fields
				query, _ = json.Marshal(res)
			}
			if field.Type().Kind() == reflect.Pointer &&
				field.Elem().IsZero() &&
				field.CanAddr() {
				// unset empty pointers
				field.SetZero()
			}
		}
	}

	return
}

// Return the field names from struct `s` that are not zero/null
func structFields(s any) []string {
	f, _ := json.Marshal(s)
	m, _ := FlattenJSONMap(f, "")
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if string(v) != "null" && string(v) != "false" && string(v) != "0" && string(v) != `""` {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

// Return the field names from map `m`
func mapFields(m map[string]any) []string {
	fields := make([]string, 0, len(m))
	for field := range m {
		fields = append(fields, field)
	}
	return fields
}
