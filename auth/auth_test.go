package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/99designs/keyring"
	"github.com/skysyzygy/tq/models"
	"github.com/stretchr/testify/assert"
)

// Setup the test environment by making a separate keystore for testing
func TestMain(m *testing.M) {
	// setup code
	Keys, _ = keyring.Open(keyring.Config{
		ServiceName: "tq_test",
	})
	code := m.Run()
	// teardown code
	os.Exit(code)
}

func TestAuth_String(t *testing.T) {
	assert := assert.New(t)

	v, err := Auth{"a", "b", "c", "d", nil}.String()
	assert.Equal(v, "a|b|c|d", "generates string")
	assert.NoError(err)

	v, err = Auth{"a|", "b", "c", "d", nil}.String()
	assert.Equal(v, "")
	assert.ErrorContains(err, "|", "complains when there are '|' present in hostname")

	v, err = Auth{"a", "b|", "c", "d", nil}.String()
	assert.Equal(v, "")
	assert.ErrorContains(err, "|", "complains when there are '|' present in username")

	v, err = Auth{"a", "b", "c|", "d", nil}.String()
	assert.Equal(v, "")
	assert.ErrorContains(err, "|", "complains when there are '|' present in usergroup")

	v, err = Auth{"a", "b", "c", "d|", nil}.String()
	assert.Equal(v, "")
	assert.ErrorContains(err, "|", "complains when there are '|' present in location")

	v, err = Auth{"a", "b", "c", "d", []byte("|)")}.String()
	assert.Equal(v, "a|b|c|d", "doesn't complain when there are '|' present in password")
	assert.NoError(err)

}

func TestFromString(t *testing.T) {
	assert := assert.New(t)

	v, err := FromString("a|b|c|d")
	assert.Equal(v, Auth{"a", "b", "c", "d", nil}, "parses string into Auth")
	assert.NoError(err)

	v, err = FromString("a|b|c|d|e")
	assert.Equal(v, Auth{})
	assert.Error(err, "four", "complains when there are too many parts in the string")

	v, err = FromString("a|b|c")
	assert.Equal(v, Auth{})
	assert.Error(err, "four", "complains when there are too few parts in the string")

}

func TestAuth_Save(t *testing.T) {
	assert := assert.New(t)

	err := Auth{"a", "b", "c", "d", []byte("e")}.Save()
	pass, _ := Keys.Get("a|b|c|d")
	assert.Equal(pass.Data, []byte("e"), "saves Auth password to keystore")
	assert.NoError(err)

}

func TestAuth_Load(t *testing.T) {
	a := Auth{"a", "b", "c", "d", nil}

	a.Load()
	assert.Equal(t, a.password, []byte("e"), "loads Auth password from keystore")
}

func TestList(t *testing.T) {
	v, err := List()

	assert.Equal(t, v, []Auth{{"a", "b", "c", "d", nil}}, "lists all auths in keystore")
	assert.NoError(t, err)

}

func TestAuth_Delete(t *testing.T) {
	k, _ := Keys.Keys()
	assert.Equal(t, len(k), 1, "there's a key in the keystore")

	err := Auth{"a", "b", "c", "d", nil}.Delete()

	k, _ = Keys.Keys()
	assert.Equal(t, len(k), 0, "deletes auth from keystore")
	assert.NoError(t, err)
}

func TestAuth_Validate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := models.AuthenticationRequest{}
		var (
			isAuthenticated bool
			message         string
		)

		reqBody, _ := io.ReadAll(r.Body)
		json.Unmarshal(reqBody, &req)

		if r.RequestURI != "/Security/Authenticate" {
			w.WriteHeader(http.StatusNotFound)
			return
		} else {
			w.Header().Set("Content-Type", "application/json")
		}

		if req.UserName == "user" &&
			req.UserGroup == "group" &&
			req.Password == "password" &&
			req.MachineLocation == "location" {
			isAuthenticated = true
		} else {
			isAuthenticated = false
			message = "bad credentials"
		}

		res := models.AuthenticationResponse{
			IsAuthenticated: isAuthenticated,
			Message:         message,
		}

		resBody, _ := json.Marshal(&res)
		w.Write(resBody)
	}))
	defer server.Close()

	url := strings.Replace(server.URL, "https://", "", 1)

	v, err := Auth{Hostname: "not-a-host.com",
		username: "user", usergroup: "group", location: "location", password: []byte("password")}.Validate()
	assert.False(t, v)
	assert.ErrorContains(t, err, "no such host", "validation fails when server is unreachable and provides useful info")

	v, err = Auth{Hostname: url + "/Not an endpoint/",
		username: "user", usergroup: "group", location: "location", password: []byte("password")}.Validate()
	assert.False(t, v)
	assert.ErrorContains(t, err, "404 Not Found", "validation fails when endpoint is incorrect and provides useful info")

	v, err = Auth{Hostname: url,
		username: "user", usergroup: "group", location: "location", password: []byte("password")}.Validate()
	assert.True(t, v, "validation works when credentials are correct")
	assert.NoError(t, err)

	v, err = Auth{Hostname: url,
		username: "user", usergroup: "group", location: "location", password: []byte("wrongPass")}.Validate()
	assert.False(t, v)
	assert.ErrorContains(t, err, "bad credentials", "validation failes when credentials are incorrect")

}

func TestAuth_Validate_Integration(t *testing.T) {

	Keys, _ = keyring.Open(keyring.Config{
		ServiceName: "tq_test_integration",
	})

	auths, _ := List()
	a := auths[0]
	a.Load()

	a1 := a
	a1.Hostname = "not-a-server.bam.org"
	v, err := a1.Validate()
	assert.False(t, v)
	assert.ErrorContains(t, err, "no such host", "validation fails when server is unreachable and provides useful info")

	a2 := a
	a2.Hostname = strings.ReplaceAll(a2.Hostname, "/TessituraService", "")
	v, err = a2.Validate()
	assert.False(t, v)
	assert.ErrorContains(t, err, "404 Not Found", "validation fails when endpoint is incorrect and provides useful info")

	v, err = a.Validate()
	assert.True(t, v, "validation works when credentials are correct")
	assert.NoError(t, err)

	a.password = []byte("wrong_password")
	v, err = a.Validate()
	assert.False(t, v)
	assert.ErrorContains(t, err, "400 Bad Request", "validation fails when credentials are incorrect")

}
