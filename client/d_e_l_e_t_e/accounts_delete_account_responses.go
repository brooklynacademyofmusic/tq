// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// AccountsDeleteAccountReader is a Reader for the AccountsDeleteAccount structure.
type AccountsDeleteAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AccountsDeleteAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewAccountsDeleteAccountNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[DELETE /CRM/Accounts/{accountId}] Accounts_DeleteAccount", response, response.Code())
	}
}

// NewAccountsDeleteAccountNoContent creates a AccountsDeleteAccountNoContent with default headers values
func NewAccountsDeleteAccountNoContent() *AccountsDeleteAccountNoContent {
	return &AccountsDeleteAccountNoContent{}
}

/*
AccountsDeleteAccountNoContent describes a response with status code 204, with default header values.

No Content
*/
type AccountsDeleteAccountNoContent struct {
}

// IsSuccess returns true when this accounts delete account no content response has a 2xx status code
func (o *AccountsDeleteAccountNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this accounts delete account no content response has a 3xx status code
func (o *AccountsDeleteAccountNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accounts delete account no content response has a 4xx status code
func (o *AccountsDeleteAccountNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this accounts delete account no content response has a 5xx status code
func (o *AccountsDeleteAccountNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this accounts delete account no content response a status code equal to that given
func (o *AccountsDeleteAccountNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the accounts delete account no content response
func (o *AccountsDeleteAccountNoContent) Code() int {
	return 204
}

func (o *AccountsDeleteAccountNoContent) Error() string {
	return fmt.Sprintf("[DELETE /CRM/Accounts/{accountId}][%d] accountsDeleteAccountNoContent ", 204)
}

func (o *AccountsDeleteAccountNoContent) String() string {
	return fmt.Sprintf("[DELETE /CRM/Accounts/{accountId}][%d] accountsDeleteAccountNoContent ", 204)
}

func (o *AccountsDeleteAccountNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}