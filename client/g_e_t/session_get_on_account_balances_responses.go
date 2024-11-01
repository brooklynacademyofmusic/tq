// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

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

// SessionGetOnAccountBalancesReader is a Reader for the SessionGetOnAccountBalances structure.
type SessionGetOnAccountBalancesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SessionGetOnAccountBalancesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSessionGetOnAccountBalancesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSessionGetOnAccountBalancesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSessionGetOnAccountBalancesOK creates a SessionGetOnAccountBalancesOK with default headers values
func NewSessionGetOnAccountBalancesOK() *SessionGetOnAccountBalancesOK {
	return &SessionGetOnAccountBalancesOK{}
}

/*
SessionGetOnAccountBalancesOK describes a response with status code 200, with default header values.

OK
*/
type SessionGetOnAccountBalancesOK struct {
	Payload []*models.OnAccountBalance
}

// IsSuccess returns true when this session get on account balances o k response has a 2xx status code
func (o *SessionGetOnAccountBalancesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this session get on account balances o k response has a 3xx status code
func (o *SessionGetOnAccountBalancesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this session get on account balances o k response has a 4xx status code
func (o *SessionGetOnAccountBalancesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this session get on account balances o k response has a 5xx status code
func (o *SessionGetOnAccountBalancesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this session get on account balances o k response a status code equal to that given
func (o *SessionGetOnAccountBalancesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the session get on account balances o k response
func (o *SessionGetOnAccountBalancesOK) Code() int {
	return 200
}

func (o *SessionGetOnAccountBalancesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Web/Session/{sessionKey}/Constituent/OnAccount][%d] sessionGetOnAccountBalancesOK %s", 200, payload)
}

func (o *SessionGetOnAccountBalancesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Web/Session/{sessionKey}/Constituent/OnAccount][%d] sessionGetOnAccountBalancesOK %s", 200, payload)
}

func (o *SessionGetOnAccountBalancesOK) GetPayload() []*models.OnAccountBalance {
	return o.Payload
}

func (o *SessionGetOnAccountBalancesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSessionGetOnAccountBalancesDefault creates a SessionGetOnAccountBalancesDefault with default headers values
func NewSessionGetOnAccountBalancesDefault(code int) *SessionGetOnAccountBalancesDefault {
	return &SessionGetOnAccountBalancesDefault{
		_statusCode: code,
	}
}

/*
SessionGetOnAccountBalancesDefault describes a response with status code -1, with default header values.

Error
*/
type SessionGetOnAccountBalancesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this session get on account balances default response has a 2xx status code
func (o *SessionGetOnAccountBalancesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this session get on account balances default response has a 3xx status code
func (o *SessionGetOnAccountBalancesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this session get on account balances default response has a 4xx status code
func (o *SessionGetOnAccountBalancesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this session get on account balances default response has a 5xx status code
func (o *SessionGetOnAccountBalancesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this session get on account balances default response a status code equal to that given
func (o *SessionGetOnAccountBalancesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the session get on account balances default response
func (o *SessionGetOnAccountBalancesDefault) Code() int {
	return o._statusCode
}

func (o *SessionGetOnAccountBalancesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Web/Session/{sessionKey}/Constituent/OnAccount][%d] Session_GetOnAccountBalances default %s", o._statusCode, payload)
}

func (o *SessionGetOnAccountBalancesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Web/Session/{sessionKey}/Constituent/OnAccount][%d] Session_GetOnAccountBalances default %s", o._statusCode, payload)
}

func (o *SessionGetOnAccountBalancesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SessionGetOnAccountBalancesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}