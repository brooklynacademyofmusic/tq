package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/99designs/keyring"
	"github.com/skysyzygy/tq/auth"
	"github.com/skysyzygy/tq/models"

	"encoding/json"
)

var authString string

func TestMain(m *testing.M) {
	server := server()
	defer server.Close()

	// Setup the test environment by making a separate keystore for testing
	keys = keyring.NewArrayKeyring(nil)

	auth_string, _ := os.LookupEnv("AUTH_STRING")
	auth_secret, _ := os.LookupEnv("AUTH_SECRET")

	keys.Set(keyring.Item{Key: auth_string, Data: []byte(auth_secret)})

	a := auth.New(strings.Replace(server.URL, "https://", "", 1), "", "", "", nil)
	a.Save(keys)
	authString, _ = a.String()

	m.Run()

	a.Delete(keys)

	os.Remove("tq.yaml")
}

func server() (server *httptest.Server) {
	methods := map[string]string{
		"^/Web/Cart/.+?/Bookings":                          "POST",
		"^/Web/Cart/.+?/Contributions/.+?/CustomData/.+?$": "PUT",
		"^/Web/Cart/.+?/CustomData/.+?$":                   "PUT",
		"^/TXN/PerformancePriceTypes$":                     "PUT",
		"^/Cache/init$":                                    "GET",
		"^/Diagnostics/Ping$":                              "HEAD",
		"^/TXN/EmailResponses$":                            "POST",
		"^/TXN/Performances/Copy$":                         "POST",
		"^/TXN/Performances/Reschedule$":                   "POST",
		"^/TXN/BulkCopySets/.+?/CopyDay$":                  "POST",
		"^/Web/Session/.+?/Logout$":                        "POST",
		"^/Web/Session/.+?/Transfer$":                      "POST",
		"^/Web/Session/.+?/Reprint$":                       "POST",
		"^/Web/Cart/.+?/Tickets/Return$":                   "POST",
		"^/Web/Cart/.+?/Tickets/ReturnWithSeat$":           "POST",
		"^/Web/Cart/.+?/Price$":                            "POST",
		"^/Web/Cart/.+?/ValidateLimits$":                   "POST",
		"^/Emails/Send$":                                   "POST",
		"^/Emails/OrderConfirmation/.+?/Send$":             "POST",
		"^/Emails/LoginCredentials/.+?/Send$":              "POST",
		"^/Emails/ConstituentInfo/.+?/Send$":               "POST",
		"^/Emails/Orders/.+?/Tickets/Send$":                "POST",
		"^/TXN/PerformancePriceLayers/Summaries$":          "POST",
		"^/TXN/PriceEvents/MoveTo$":                        "PUT",
		"^/Web/Cart/.+?/LineItems/.+?/PriceTypeId$":        "PUT",
		"^/Web/Cart/.+?/SubLineItems/.+?/PriceTypeId$":     "PUT",
		"^/Web/Cart/.+?/SubLineItems/.+?/Recipient$":       "PUT",
		"^/Web/Cart/.+?/LineItems/.+?/SpecialRequest$":     "PUT",
		"^/Reporting/ReportRequests/FlushIncomplete$":      "PUT",
		"^/TXN/PerformancePriceTypes/Base":                 "PUT",
		"^/TXN/PerformancePriceLayers/Prices$":             "PUT",
	}

	regexes := make(map[string]*regexp.Regexp)
	for url := range methods {
		regexes[url] = regexp.MustCompile(url)
	}

	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resBody []byte
		w.Header().Set("Content-Type", "application/json")

		if r.RequestURI == "/Security/Authenticate" {
			res := models.AuthenticationResponse{
				IsAuthenticated: true,
				Message:         "",
			}
			resBody, _ = json.Marshal(&res)
		}

		for url, regex := range regexes {
			if regex.MatchString(r.RequestURI) && r.Method == methods[url] {
				w.WriteHeader(204)
			}
		}

		w.Write(resBody)
	}))
	return
}
