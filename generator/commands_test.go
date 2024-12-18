package main

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/skysyzygy/tq/client"
	"github.com/stretchr/testify/assert"
)

func Test_Describe(t *testing.T) {

	short, long, resource := describe("ConstituentsGet")
	assert.Equal(t, "Constituents", short)
	assert.Equal(t, "/CRM/Constituents", resource)
	assert.Equal(t, "Get the details of a Constituent using id.", long)

	short, long, resource = describe("ConstituentsUpdate")
	assert.Equal(t, "Constituents", short)
	assert.Equal(t, "/CRM/Constituents", resource)
	assert.Equal(t, "Update a constituent. Only the information about constituent can be updated. If addresses, electronicAddresses, salutations or phones data are passed, they will be ignored.", long)

	short, long, resource = describe("ConstituentsCreateConstituent")
	assert.Equal(t, "Constituents", short)
	assert.Equal(t, "/CRM/Constituents/Detail", resource)
	assert.Equal(t, "Create a new constituent with addresses, electronicAddresses, salutations and phones.", long)

	short, long, resource = describe("ElectronicAddressesGet")
	assert.Equal(t, "ElectronicAddresses", short)
	assert.Equal(t, "/CRM/ElectronicAddresses", resource)
	assert.Equal(t, "Get details of an electronic address.", long)

	short, long, resource = describe("ElectronicAddressesUpdate")
	assert.Equal(t, "ElectronicAddresses", short)
	assert.Equal(t, "/CRM/ElectronicAddresses", resource)
	assert.Equal(t, "Update an electronic address.", long)

	short, long, resource = describe("ElectronicAddressesCreate")
	assert.Equal(t, "ElectronicAddresses", short)
	assert.Equal(t, "/CRM/ElectronicAddresses", resource)
	assert.Equal(t, "Create a new electronic address.", long)

	short, long, resource = describe("AssociationTypesGet")
	assert.Equal(t, "AssociationTypes", short)
	assert.Equal(t, "/ReferenceData/AssociationTypes", resource)
	assert.Equal(t, "Get the details of an association type by id. To get the resource only if the user has write/edit access, pass filter=\"writeonly\". To get the resources in maintenance mode(ignore Control Groups), pass maintenanceMode=\"true\". Maintenance mode requires users to have access to the reference tables. (Specified in TX_REFTABLE_USERGROUP).", long)

}

// Test that instantiateStructType recurses into a struct, navigating pointers, and initializes
// strings with "string" and everything else with zero type
func Test_instantiateStructType(t *testing.T) {
	type test struct {
		I  int
		F  float32
		B  bool
		S  string
		SP *string
	}
	type nest struct {
		P *test
		O test
	}
	type arrayobj struct {
		A  []test
		AP *[]test
	}
	pointer := new(nest)
	object := *pointer
	arrays := new(arrayobj)
	s, i := instantiateStructType(reflect.TypeOf(object), 1)
	j, _ := json.Marshal(s)
	assert.Equal(t,
		`{"P":{"I":123,"F":123.456,"B":true,"S":"string","SP":"string"},"O":{"I":123,"F":123.456,"B":true,"S":"string","SP":"string"}}`,
		string(j))
	assert.Equal(t, i, 1)

	s, i = instantiateStructType(reflect.TypeOf(pointer), 1)
	j, _ = json.Marshal(s)
	assert.Equal(t,
		`{"P":{"I":123,"F":123.456,"B":true,"S":"string","SP":"string"},"O":{"I":123,"F":123.456,"B":true,"S":"string","SP":"string"}}`,
		string(j))
	assert.Equal(t, i, 1)

	// only initialize the root object
	s, i = instantiateStructType(reflect.TypeOf(pointer), 0)
	j, _ = json.Marshal(s)
	assert.Equal(t,
		`{"P":null,"O":{"I":0,"F":0,"B":false,"S":"","SP":null}}`,
		string(j))
	assert.Equal(t, i, 0)

	s, i = instantiateStructType(reflect.TypeOf(arrays), 0)
	j, _ = json.Marshal(s)
	assert.Equal(t,
		`{"A":null,"AP":null}`,
		string(j))
	assert.Equal(t, i, 0)

	s, i = instantiateStructType(reflect.TypeOf(arrays), 1)
	j, _ = json.Marshal(s)
	assert.Equal(t,
		`{"A":[{"I":123,"F":123.456,"B":true,"S":"string","SP":"string"}],"AP":[{"I":123,"F":123.456,"B":true,"S":"string","SP":"string"}]}`,
		string(j))
	assert.Equal(t, i, 1)

}

func Test_usage(t *testing.T) {
	client := client.New(nil, nil)
	method, _ := reflect.TypeOf(client.Get).MethodByName("ConstituentsGet")
	assert.Equal(t, `{"ConstituentID":"string"}`, usage(method))
	//assert.Equal(t,  1,  len(usage(method)))
	method, _ = reflect.TypeOf(client.Put).MethodByName("ConstituentsUpdate")
	//assert.Equal(t,  `{"Constituent":{"ConstituentType":{"Id":123}, "CreateLocation":"string", "CreatedBy":"string", "CreatedDateTime":"2000-01-01T00:00:00.000Z", "DisplayName":"string", "EmarketIndicator":{"Id":123}, "FirstName":"string", "Gender":{"Id":123}, "Id":123, "Inactive":{"Id":123}, "InactiveReason":{"Id":123}, "LastActivityDate":"2000-01-01T00:00:00.000Z", "LastGiftDate":"2000-01-01T00:00:00.000Z", "LastName":"string", "LastTicketDate":"2000-01-01T00:00:00.000Z", "MailIndicator":{"Id":123}, "MiddleName":"string", "NameStatus":{"Id":123}, "OriginalSource":{"Id":123}, "PhoneIndicator":{"Id":123}, "Prefix":{"Id":123}, "ProtectionType":{"Id":123}, "SortName":"string", "Suffix":{"Id":123}, "UpdatedBy":"string", "UpdatedDateTime":"2000-01-01T00:00:00.000Z"}, "ConstituentID":"string"}`,  usage(method)[0])
	assert.Equal(t, `{"ConstituentType":{"Id":123}, "CreateLocation":"string", "CreatedBy":"string", "CreatedDateTime":"2000-01-01T00:00:00.000Z", "DisplayName":"string", "EmarketIndicator":{"Id":123}, "FirstName":"string", "Gender":{"Id":123}, "Id":123, "Inactive":{"Id":123}, "InactiveReason":{"Id":123}, "LastActivityDate":"2000-01-01T00:00:00.000Z", "LastGiftDate":"2000-01-01T00:00:00.000Z", "LastName":"string", "LastTicketDate":"2000-01-01T00:00:00.000Z", "MailIndicator":{"Id":123}, "MiddleName":"string", "NameStatus":{"Id":123}, "OriginalSource":{"Id":123}, "PhoneIndicator":{"Id":123}, "Prefix":{"Id":123}, "ProtectionType":{"Id":123}, "SortName":"string", "Suffix":{"Id":123}, "UpdatedBy":"string", "UpdatedDateTime":"2000-01-01T00:00:00.000Z", "ConstituentID":"string"}`, usage(method))
	method, _ = reflect.TypeOf(client.Post).MethodByName("ConstituentsCreateConstituent")
	//assert.Equal(t,  `{"Constituent":{"Addresses":[{"Id":123}, ...], "ConstituentType":{"Id":123}, "CreateLocation":"string", "CreatedBy":"string", "CreatedDateTime":"2000-01-01T00:00:00.000Z", "DisplayName":"string", "ElectronicAddresses":[{"Id":123}, ...], "EmarketIndicator":{"Id":123}, "FirstName":"string", "Gender":{"Id":123}, "Id":123, "Inactive":{"Id":123}, "InactiveReason":{"Id":123}, "LastActivityDate":"2000-01-01T00:00:00.000Z", "LastGiftDate":"2000-01-01T00:00:00.000Z", "LastName":"string", "LastTicketDate":"2000-01-01T00:00:00.000Z", "MailIndicator":{"Id":123}, "MiddleName":"string", "NameStatus":{"Id":123}, "OriginalSource":{"Id":123}, "PhoneIndicator":{"Id":123}, "PhoneNumbers":[{"Id":123}, ...], "Prefix":{"Id":123}, "ProtectionType":{"Id":123}, "Salutations":[{"Id":123}, ...], "SortName":"string", "Suffix":{"Id":123}, "UpdatedBy":"string", "UpdatedDateTime":"2000-01-01T00:00:00.000Z"}}`,  usage(method)[0])
	assert.Equal(t, `{"Addresses":[{"Id":123}, ...], "ConstituentType":{"Id":123}, "CreateLocation":"string", "CreatedBy":"string", "CreatedDateTime":"2000-01-01T00:00:00.000Z", "DisplayName":"string", "ElectronicAddresses":[{"Id":123}, ...], "EmarketIndicator":{"Id":123}, "FirstName":"string", "Gender":{"Id":123}, "Id":123, "Inactive":{"Id":123}, "InactiveReason":{"Id":123}, "LastActivityDate":"2000-01-01T00:00:00.000Z", "LastGiftDate":"2000-01-01T00:00:00.000Z", "LastName":"string", "LastTicketDate":"2000-01-01T00:00:00.000Z", "MailIndicator":{"Id":123}, "MiddleName":"string", "NameStatus":{"Id":123}, "OriginalSource":{"Id":123}, "PhoneIndicator":{"Id":123}, "PhoneNumbers":[{"Id":123}, ...], "Prefix":{"Id":123}, "ProtectionType":{"Id":123}, "Salutations":[{"Id":123}, ...], "SortName":"string", "Suffix":{"Id":123}, "UpdatedBy":"string", "UpdatedDateTime":"2000-01-01T00:00:00.000Z"}`, usage(method))
	method, _ = reflect.TypeOf(client.Post).MethodByName("AccountTypesCreate")
	//assert.Equal(t,  `{"Data":{"CardLength":"string", "CardPrefix":"string", "CardtypeIndicator":"string", "CreateLocation":"string", "CreatedBy":"string", "CreatedDateTime":"2000-01-01T00:00:00.000Z", "Description":"string", "EditMask":"string", "Id":123, "Inactive":true, "Mod10Indicator":"string", "UpdatedBy":"string", "UpdatedDateTime":"2000-01-01T00:00:00.000Z"}}`,  usage(method)[0])
	assert.Equal(t, `{"CardLength":"string", "CardPrefix":"string", "CardtypeIndicator":"string", "CreateLocation":"string", "CreatedBy":"string", "CreatedDateTime":"2000-01-01T00:00:00.000Z", "Description":"string", "EditMask":"string", "Id":123, "Inactive":true, "Mod10Indicator":"string", "UpdatedBy":"string", "UpdatedDateTime":"2000-01-01T00:00:00.000Z"}`, usage(method))
	method, _ = reflect.TypeOf(client.Post).MethodByName("InterestsCreateOrUpdate")
	//assert.Equal(t,  `{"Data":{"CardLength":"string", "CardPrefix":"string", "CardtypeIndicator":"string", "CreateLocation":"string", "CreatedBy":"string", "CreatedDateTime":"2000-01-01T00:00:00.000Z", "Description":"string", "EditMask":"string", "Id":123, "Inactive":true, "Mod10Indicator":"string", "UpdatedBy":"string", "UpdatedDateTime":"2000-01-01T00:00:00.000Z"}}`,  usage(method)[0])
	assert.Equal(t, `{"Interests":[{"Constituent":{"Id":123}, "CreateLocation":"string", "CreatedBy":"string", "CreatedDateTime":"2000-01-01T00:00:00.000Z", "EditIndicator":true, "Id":123, "InterestType":{"Id":123}, "Selected":true, "UpdatedBy":"string", "UpdatedDateTime":"2000-01-01T00:00:00.000Z", "Weight":123}, ...]}`, usage(method))
}

func Test_newCommandGet(t *testing.T) {
	client := client.New(nil, nil)
	c := reflect.TypeOf(client.Get)
	commands := make([]command, c.NumMethod())
	commandMap := make(map[string]bool)
	for i := 0; i < c.NumMethod(); i++ {
		if methodName := c.Method(i).Name; slices.Contains([]string{
			"SetTransport", "CacheInit", "DiagnosticsGetAPIPluginConfiguration"},
			methodName) {
			continue
		}
		commands[i] = newCommand(c.Method(i))
		assert.NotEqual(t, "", commands[i].Verb, commands[i])
		assert.NotEqual(t, "", commands[i].Thing, commands[i])
		// Test that each verb/thing/variant is unique
		commandHash := commands[i].Verb + "_" + commands[i].Thing + "_" + commands[i].Variant
		assert.False(t, commandMap[commandHash], commandHash)
		commandMap[commandHash] = true
	}
}

func Test_newCommandPut(t *testing.T) {
	client := client.New(nil, nil)
	c := reflect.TypeOf(client.Put)
	commands := make([]command, c.NumMethod())
	commandMap := make(map[string]bool)
	for i := 0; i < c.NumMethod(); i++ {
		if methodName := c.Method(i).Name; slices.Contains([]string{
			"SetTransport", "DiagnosticsPut"},
			methodName) {
			continue
		}
		commands[i] = newCommand(c.Method(i))
		assert.NotEqual(t, "", commands[i].Verb, commands[i])
		assert.NotEqual(t, "", commands[i].Thing, commands[i])
		// Test that each verb/thing/variant is unique
		commandHash := commands[i].Verb + "_" + commands[i].Thing + "_" + commands[i].Variant
		assert.False(t, commandMap[commandHash], commandHash)
		commandMap[commandHash] = true
	}
}

func Test_newCommandPost(t *testing.T) {
	client := client.New(nil, nil)
	c := reflect.TypeOf(client.Post)
	commands := make([]command, c.NumMethod())
	commandMap := make(map[string]bool)

	for i := 0; i < c.NumMethod(); i++ {
		if methodName := c.Method(i).Name; slices.Contains([]string{
			"SetTransport",
			"EmailsSendTickets", "OrdersPrintHTMLTickets"},
			methodName) {
			continue
		}
		commands[i] = newCommand(c.Method(i))
		assert.NotEqual(t, "", commands[i].Verb, commands[i])
		assert.NotEqual(t, "", commands[i].Thing, commands[i])
		// Test that each verb/thing/variant is unique
		commandHash := commands[i].Verb + "_" + commands[i].Thing + "_" + commands[i].Variant
		assert.False(t, commandMap[commandHash], commandHash)
		commandMap[commandHash] = true
	}
}

func Test_makeAliases(t *testing.T) {
	assert.Equal(t, makeAliases("lowercase"), []string{})
	assert.ElementsMatch(t, makeAliases("Titlecase"), []string{"t", "T", "titlecase"})
	assert.ElementsMatch(t, makeAliases("UPPERCASE"), []string{"uppercase"})
	assert.ElementsMatch(t, makeAliases("CamelCase"), []string{
		"CC", "cc", "camelcase",
	})
}
