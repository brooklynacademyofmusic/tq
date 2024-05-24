// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// AccountsUpdateSepaAccountReader is a Reader for the AccountsUpdateSepaAccount structure.
type AccountsUpdateSepaAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AccountsUpdateSepaAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAccountsUpdateSepaAccountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAccountsUpdateSepaAccountDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAccountsUpdateSepaAccountOK creates a AccountsUpdateSepaAccountOK with default headers values
func NewAccountsUpdateSepaAccountOK() *AccountsUpdateSepaAccountOK {
	return &AccountsUpdateSepaAccountOK{}
}

/*
AccountsUpdateSepaAccountOK describes a response with status code 200, with default header values.

OK
*/
type AccountsUpdateSepaAccountOK struct {
	Payload *models.AccountResponse
}

// IsSuccess returns true when this accounts update sepa account o k response has a 2xx status code
func (o *AccountsUpdateSepaAccountOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this accounts update sepa account o k response has a 3xx status code
func (o *AccountsUpdateSepaAccountOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accounts update sepa account o k response has a 4xx status code
func (o *AccountsUpdateSepaAccountOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this accounts update sepa account o k response has a 5xx status code
func (o *AccountsUpdateSepaAccountOK) IsServerError() bool {
	return false
}

// IsCode returns true when this accounts update sepa account o k response a status code equal to that given
func (o *AccountsUpdateSepaAccountOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the accounts update sepa account o k response
func (o *AccountsUpdateSepaAccountOK) Code() int {
	return 200
}

func (o *AccountsUpdateSepaAccountOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Accounts/{accountId}/SEPA][%d] accountsUpdateSepaAccountOK %s", 200, payload)
}

func (o *AccountsUpdateSepaAccountOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Accounts/{accountId}/SEPA][%d] accountsUpdateSepaAccountOK %s", 200, payload)
}

func (o *AccountsUpdateSepaAccountOK) GetPayload() *models.AccountResponse {
	return o.Payload
}

func (o *AccountsUpdateSepaAccountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AccountResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAccountsUpdateSepaAccountDefault creates a AccountsUpdateSepaAccountDefault with default headers values
func NewAccountsUpdateSepaAccountDefault(code int) *AccountsUpdateSepaAccountDefault {
	return &AccountsUpdateSepaAccountDefault{
		_statusCode: code,
	}
}

/*
AccountsUpdateSepaAccountDefault describes a response with status code -1, with default header values.

Error
*/
type AccountsUpdateSepaAccountDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this accounts update sepa account default response has a 2xx status code
func (o *AccountsUpdateSepaAccountDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this accounts update sepa account default response has a 3xx status code
func (o *AccountsUpdateSepaAccountDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this accounts update sepa account default response has a 4xx status code
func (o *AccountsUpdateSepaAccountDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this accounts update sepa account default response has a 5xx status code
func (o *AccountsUpdateSepaAccountDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this accounts update sepa account default response a status code equal to that given
func (o *AccountsUpdateSepaAccountDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the accounts update sepa account default response
func (o *AccountsUpdateSepaAccountDefault) Code() int {
	return o._statusCode
}

func (o *AccountsUpdateSepaAccountDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Accounts/{accountId}/SEPA][%d] Accounts_UpdateSepaAccount default %s", o._statusCode, payload)
}

func (o *AccountsUpdateSepaAccountDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Accounts/{accountId}/SEPA][%d] Accounts_UpdateSepaAccount default %s", o._statusCode, payload)
}

func (o *AccountsUpdateSepaAccountDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AccountsUpdateSepaAccountDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
