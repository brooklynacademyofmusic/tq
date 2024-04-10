// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// AccountsGetAllReader is a Reader for the AccountsGetAll structure.
type AccountsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AccountsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAccountsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /CRM/Accounts] Accounts_GetAll", response, response.Code())
	}
}

// NewAccountsGetAllOK creates a AccountsGetAllOK with default headers values
func NewAccountsGetAllOK() *AccountsGetAllOK {
	return &AccountsGetAllOK{}
}

/*
AccountsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type AccountsGetAllOK struct {
	Payload []*models.AccountResponse
}

// IsSuccess returns true when this accounts get all o k response has a 2xx status code
func (o *AccountsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this accounts get all o k response has a 3xx status code
func (o *AccountsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accounts get all o k response has a 4xx status code
func (o *AccountsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this accounts get all o k response has a 5xx status code
func (o *AccountsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this accounts get all o k response a status code equal to that given
func (o *AccountsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the accounts get all o k response
func (o *AccountsGetAllOK) Code() int {
	return 200
}

func (o *AccountsGetAllOK) Error() string {
	return fmt.Sprintf("[GET /CRM/Accounts][%d] accountsGetAllOK  %+v", 200, o.Payload)
}

func (o *AccountsGetAllOK) String() string {
	return fmt.Sprintf("[GET /CRM/Accounts][%d] accountsGetAllOK  %+v", 200, o.Payload)
}

func (o *AccountsGetAllOK) GetPayload() []*models.AccountResponse {
	return o.Payload
}

func (o *AccountsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}