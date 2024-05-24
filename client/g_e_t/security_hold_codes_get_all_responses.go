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

// SecurityHoldCodesGetAllReader is a Reader for the SecurityHoldCodesGetAll structure.
type SecurityHoldCodesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SecurityHoldCodesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSecurityHoldCodesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSecurityHoldCodesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSecurityHoldCodesGetAllOK creates a SecurityHoldCodesGetAllOK with default headers values
func NewSecurityHoldCodesGetAllOK() *SecurityHoldCodesGetAllOK {
	return &SecurityHoldCodesGetAllOK{}
}

/*
SecurityHoldCodesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type SecurityHoldCodesGetAllOK struct {
	Payload []*models.HoldCodeUserGroup
}

// IsSuccess returns true when this security hold codes get all o k response has a 2xx status code
func (o *SecurityHoldCodesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this security hold codes get all o k response has a 3xx status code
func (o *SecurityHoldCodesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this security hold codes get all o k response has a 4xx status code
func (o *SecurityHoldCodesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this security hold codes get all o k response has a 5xx status code
func (o *SecurityHoldCodesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this security hold codes get all o k response a status code equal to that given
func (o *SecurityHoldCodesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the security hold codes get all o k response
func (o *SecurityHoldCodesGetAllOK) Code() int {
	return 200
}

func (o *SecurityHoldCodesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/HoldCodes][%d] securityHoldCodesGetAllOK %s", 200, payload)
}

func (o *SecurityHoldCodesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/HoldCodes][%d] securityHoldCodesGetAllOK %s", 200, payload)
}

func (o *SecurityHoldCodesGetAllOK) GetPayload() []*models.HoldCodeUserGroup {
	return o.Payload
}

func (o *SecurityHoldCodesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSecurityHoldCodesGetAllDefault creates a SecurityHoldCodesGetAllDefault with default headers values
func NewSecurityHoldCodesGetAllDefault(code int) *SecurityHoldCodesGetAllDefault {
	return &SecurityHoldCodesGetAllDefault{
		_statusCode: code,
	}
}

/*
SecurityHoldCodesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type SecurityHoldCodesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this security hold codes get all default response has a 2xx status code
func (o *SecurityHoldCodesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this security hold codes get all default response has a 3xx status code
func (o *SecurityHoldCodesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this security hold codes get all default response has a 4xx status code
func (o *SecurityHoldCodesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this security hold codes get all default response has a 5xx status code
func (o *SecurityHoldCodesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this security hold codes get all default response a status code equal to that given
func (o *SecurityHoldCodesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the security hold codes get all default response
func (o *SecurityHoldCodesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *SecurityHoldCodesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/HoldCodes][%d] SecurityHoldCodes_GetAll default %s", o._statusCode, payload)
}

func (o *SecurityHoldCodesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/HoldCodes][%d] SecurityHoldCodes_GetAll default %s", o._statusCode, payload)
}

func (o *SecurityHoldCodesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SecurityHoldCodesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
