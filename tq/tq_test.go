package tq

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/skysyzygy/tq/auth"
	"github.com/skysyzygy/tq/client/g_e_t"
	"github.com/skysyzygy/tq/models"
	"github.com/stretchr/testify/assert"
)

func Test_NewLogging(t *testing.T) {
	r, w, _ := os.Pipe()
	fileOutput := make([]byte, 1024)
	defer w.Close()

	_, consoleOutput := CaptureOutput(func() {
		tq := New(w, false, false)

		tq.Log.Warn("Warn")
		tq.Log.Info("Info")
	})

	r.Read(fileOutput)
	// With standard logging the console only prints warnings/errors
	assert.Contains(t, string(fileOutput), "Warn")
	assert.Contains(t, string(consoleOutput), "Warn")
	assert.NotContains(t, string(consoleOutput), "Info")

	_, consoleOutput = CaptureOutput(func() {
		tq := New(w, true, false)

		tq.Log.Info("Info")
		tq.Log.Debug("Debug")
	})

	// With verbose logging the console also prints info
	assert.Contains(t, string(consoleOutput), "Info")
	assert.NotContains(t, string(consoleOutput), "Debug")

}

func Test_unmarshallStructWithRemainder(t *testing.T) {
	type P struct{ A, B, C string }
	type Q map[string]any

	// test that unmarshallWithRemainder fills struct and returns map of extra data
	p := new(P)
	res, err := unmarshallStructWithRemainder([]byte(`{"A": "these", "B": "are", "C": "words"}`), p)
	assert.Equal(t, P{"these", "are", "words"}, *p)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(res))

	p = new(P)
	res, err = unmarshallStructWithRemainder([]byte(`{"A": "these", "B": "are", "C": "words", "D": "nothing", "E": "more"}`), p)
	assert.Equal(t, P{"these", "are", "words"}, *p)
	assert.NoError(t, err)
	assert.Equal(t, Q{"D": "nothing", "E": "more"}, Q(res))

	// test that unmarshallWithRemainder returns an error if it's asked to fill a non-struct
	q := new(Q)
	res, err = unmarshallStructWithRemainder([]byte(`{"A": "these", "B": "are", "C": "words"}`), q)
	assert.Equal(t, Q(nil), *q)
	assert.ErrorContains(t, err, "must be pointer to struct")
	assert.Equal(t, Q(nil), Q(res))

	// test that unmarshallWithRemainder returns an error if it's given a JSON array
	p = new(P)
	res, err = unmarshallStructWithRemainder([]byte(`[{"A": "these", "B": "are", "C": "words"}]`), p)
	assert.ErrorContains(t, err, "cannot unmarshal array")
	assert.Equal(t, Q(nil), Q(res))

}

func Test_unmarshallNestedStructWithRemainder(t *testing.T) {
	type P struct{ A, B, C string }
	type N struct {
		D, E, F string
		Nest    P
	}
	type NP struct {
		D, E, F string
		Nest    *P
	}

	// test that unmarshallNestedWithRemainder fills nested struct and returns map of extra data
	n := new(N)
	res, err := unmarshallNestedStructWithRemainder([]byte(`{"A": "these", "B": "are", "C": "words"}`), n, nil)
	assert.Equal(t, N{Nest: P{"these", "are", "words"}}, *n)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(res))

	n = new(N)
	res, err = unmarshallNestedStructWithRemainder([]byte(`{"A": "these", "B": "are", "C": "words", "D": "nothing", "E": "more"}`), n, nil)
	assert.Equal(t, N{D: "nothing", E: "more", Nest: P{"these", "are", "words"}}, *n)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(res))

	n = new(N)
	res, err = unmarshallNestedStructWithRemainder([]byte(`{"A": "these", "B": "are", "C": "words", "D": "nothing", "Z": "zzz"}`), n, nil)
	assert.Equal(t, N{D: "nothing", Nest: P{"these", "are", "words"}}, *n)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(res))
	assert.Equal(t, map[string]any{"Z": "zzz"}, res)

	// test that unmarshallNestedWithRemainder fills pointer to nested struct and returns map of extra data
	np := new(NP)
	res, err = unmarshallNestedStructWithRemainder([]byte(`{"A": "these", "B": "are", "C": "words"}`), np, nil)
	assert.Equal(t, NP{Nest: &P{"these", "are", "words"}}, *np)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(res))

	np = new(NP)
	res, err = unmarshallNestedStructWithRemainder([]byte(`{"A": "these", "B": "are", "C": "words", "D": "nothing", "E": "more"}`), np, nil)
	assert.Equal(t, NP{D: "nothing", E: "more", Nest: &P{"these", "are", "words"}}, *np)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(res))

	np = new(NP)
	res, err = unmarshallNestedStructWithRemainder([]byte(`{"A": "these", "B": "are", "C": "words", "D": "nothing", "Z": "zzz"}`), np, nil)
	assert.Equal(t, NP{D: "nothing", Nest: &P{"these", "are", "words"}}, *np)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(res))
	assert.Equal(t, map[string]any{"Z": "zzz"}, res)
}

// Test that unmarshallNestedStructWithRemainder doesn't recurse into `except`ed fields
func Test_unmarshallNestedStructWithRemainder_Noop(t *testing.T) {
	type P struct{ A, B, C string }
	type N struct {
		D, E, F string
		Nest    P
	}
	type NP struct {
		D, E, F string
		Nest    *P
	}

	// test that unmarshallNestedWithRemainder fills nested struct and returns map of extra data
	n := new(N)
	res, err := unmarshallNestedStructWithRemainder([]byte(`{"A": "these", "B": "are", "D": "just", "C": "words"}`), n, []string{"Nest"})
	assert.Equal(t, N{Nest: P{}, D: "just"}, *n)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(res))

	np := new(NP)
	res, err = unmarshallNestedStructWithRemainder([]byte(`{"A": "these", "B": "are", "D": "just", "C": "words"}`), np, []string{"Nest"})
	assert.Equal(t, NP{Nest: nil, D: "just"}, *np)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(res))
}

func Test_unmarshallNestedStructWithRemainder_Conflict(t *testing.T) {
	type B struct {
		ID int `json:"Id"`
	}
	type A struct {
		ID  string
		Obj *B
	}

	a := new(A)
	res, err := unmarshallStructWithRemainder([]byte(`{"ID":"string","Id":123}`), a)
	assert.Equal(t, A{"string", nil}, *a)
	assert.Regexp(t, "cannot unmarshal number into .+ type string", err.Error())
	assert.Equal(t, 1, len(res))

	a = new(A)
	res, err = unmarshallNestedStructWithRemainder([]byte(`{"ID":"string","Id":123}`), a, nil)
	assert.Equal(t, A{"string", &B{123}}, *a)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(res))

}

// test that structFields returns used elements of struct pointer, string, and int types
func Test_structFields(t *testing.T) {

	strings := []string{"these", "are", "words"}
	pp := struct{ A, B, C, empty *string }{&strings[0], &strings[1], &strings[2], nil}
	ps := struct{ A, B, C, empty string }{strings[0], strings[1], strings[2], ""}
	pi := struct{ A, B, C, empty int }{1, 2, 3, 0}
	ppp := &pp
	pps := &ps
	ppi := &pi

	assert.Equal(t, []string{"A", "B", "C"}, structFields(pp))
	assert.Equal(t, []string{"A", "B", "C"}, structFields(ps))
	assert.Equal(t, []string{"A", "B", "C"}, structFields(pi))
	assert.Equal(t, []string{"A", "B", "C"}, structFields(ppp))
	assert.Equal(t, []string{"A", "B", "C"}, structFields(pps))
	assert.Equal(t, []string{"A", "B", "C"}, structFields(ppi))

}

// test that mapFields returns map keys
func Test_mapFields(t *testing.T) {
	m := map[string]any{"hi": []string{}, "i'm": 1, "a": false, "map": "!"}
	keys := reflect.ValueOf(m).MapKeys()
	keyString := make([]string, len(keys))
	for i, key := range keys {
		keyString[i] = key.String()
	}
	assert.ElementsMatch(t, []string{"hi", "i'm", "a", "map"}, mapFields(m))
	assert.ElementsMatch(t, []string{"hi", "i'm", "a", "map"}, keyString)
}

// test that Login builds Tessitura API client and saves BasicAuth info for future use
func Test_Login(t *testing.T) {
	tq := New(nil, false, false)
	tq.Login(auth.New("hostname", "user", "", "", nil))
	assert.NotNil(t, tq.Get)
	assert.NotNil(t, tq.basicAuth)
}

func testServer(t *testing.T) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := g_e_t.ConstituentsGetConstituentParams{}

		// Check that the caller is authenticated
		assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte(`user:::password`)),
			r.Header.Values("Authorization")[0])

		reqBody, _ := io.ReadAll(r.Body)
		json.Unmarshal(reqBody, &req)

		id, _ := strconv.Atoi(strings.Split(r.URL.Path, "/")[3])

		resBody, _ := json.Marshal(models.Constituent{
			ID:        int32(id),
			FirstName: "Test",
			LastName:  "User",
		})

		// return error because 0 is not allowed
		if strings.Contains(r.URL.Path, "0") {
			w.WriteHeader(400)
			w.Write([]byte("ERROR: ConstituentID 0 is not allowed"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(resBody)
	}))
}

// test that DoOne calls swagger API functions and returns a response
func Test_DoOne(t *testing.T) {
	oneConstituent := models.Constituent{
		ID:        1,
		FirstName: "Test",
		LastName:  "User",
	}
	oneConstituentDetail := models.ConstituentDetail{
		ID:        0,
		FirstName: "Test",
		LastName:  "User",
	}
	server := testServer(t)
	defer server.Close()
	tq := New(nil, false, false)
	query := []byte(`{"ConstituentId": "0"}`)
	tq.Login(auth.New(strings.Replace(server.URL, "https://", "", 1), "user", "", "", []byte("password")))

	res, err := DoOne(*tq, tq.Get.ConstituentsGet, query)
	assert.Equal(t, []byte(nil), res)
	assert.ErrorContains(t, err, "ERROR: ConstituentID 0 is not allowed")

	query = []byte(`{"ConstituentId": "1"}`)

	res, err = DoOne(*tq, tq.Get.ConstituentsGet, query)
	expectedJSON, _ := json.Marshal(oneConstituent)
	assert.Equal(t, expectedJSON, res)
	assert.NoError(t, err)

	res, err = DoOne(*tq, tq.Put.ConstituentsUpdate, query)
	expectedJSON, _ = json.Marshal(oneConstituent)
	assert.Equal(t, expectedJSON, res)
	assert.NoError(t, err)

	query = []byte(`{"Constituent": {"FirstName": "Test"}}`)
	res, err = DoOne(*tq, tq.Post.ConstituentsCreateConstituent, query)
	expectedJSON, _ = json.Marshal(oneConstituentDetail)
	assert.Equal(t, expectedJSON, res)
	assert.NoError(t, err)

}

// Test that DoOne does nothing when there's no data given
func Test_DoOneNoop(t *testing.T) {
	server := testServer(t)
	defer server.Close()
	tq := New(nil, false, false)
	query := []byte(`{"Not a key": 0}`)
	tq.Login(auth.New(strings.Replace(server.URL, "https://", "", 1), "user", "", "", []byte("password")))

	res, err := DoOne(*tq, tq.Get.ConstituentsGet, query)
	assert.Equal(t, []byte(nil), res)
	assert.Regexp(t, "query could not be parsed", err.Error())

}

// Test that Do dispatches to DoOne singularly or in parallel depending on query
// and returns valid JSON
func Test_Do(t *testing.T) {
	server := testServer(t)
	defer server.Close()
	tq := New(nil, false, false)
	tq.Login(auth.New(strings.Replace(server.URL, "https://", "", 1), "user", "", "", []byte("password")))

	query := []byte(`{"ConstituentId": "0"}`)
	constituent := new(models.Constituent)
	res, err := Do(*tq, tq.Get.ConstituentsGet, query)
	json.Unmarshal(res, constituent)
	assert.Equal(t, int32(0), constituent.ID)
	assert.NoError(t, err)

	query = []byte(`[{"ConstituentId": "1"},{"ConstituentId": "2"},{"ConstituentId": "3"}]`)
	constituents := new([]models.Constituent)
	res, err = Do(*tq, tq.Get.ConstituentsGet, query)
	json.Unmarshal(res, constituents)
	assert.Equal(t, 3, len(*constituents))
	assert.Equal(t, int32(1), (*constituents)[0].ID)
	assert.Equal(t, int32(2), (*constituents)[1].ID)
	assert.Equal(t, int32(3), (*constituents)[2].ID)
	assert.NoError(t, err)

	// Test that Do returns the last error
	query = []byte(`[{"ConstituentId": "4"},["Can't be unmarshaled"],{"ConstituentId": "6"}]`)
	constituents = new([]models.Constituent)
	res, err = Do(*tq, tq.Get.ConstituentsGet, query)
	json.Unmarshal(res, constituents)
	assert.Equal(t, 3, len(*constituents))
	assert.Equal(t, int32(4), (*constituents)[0].ID)
	assert.Equal(t, int32(0), (*constituents)[1].ID)
	assert.Equal(t, int32(6), (*constituents)[2].ID)
	assert.ErrorContains(t, err, "cannot unmarshal array")
}
