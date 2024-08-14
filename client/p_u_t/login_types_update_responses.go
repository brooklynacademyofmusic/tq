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

// LoginTypesUpdateReader is a Reader for the LoginTypesUpdate structure.
type LoginTypesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *LoginTypesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewLoginTypesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewLoginTypesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewLoginTypesUpdateOK creates a LoginTypesUpdateOK with default headers values
func NewLoginTypesUpdateOK() *LoginTypesUpdateOK {
	return &LoginTypesUpdateOK{}
}

/*
LoginTypesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type LoginTypesUpdateOK struct {
	Payload *models.LoginType
}

// IsSuccess returns true when this login types update o k response has a 2xx status code
func (o *LoginTypesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this login types update o k response has a 3xx status code
func (o *LoginTypesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this login types update o k response has a 4xx status code
func (o *LoginTypesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this login types update o k response has a 5xx status code
func (o *LoginTypesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this login types update o k response a status code equal to that given
func (o *LoginTypesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the login types update o k response
func (o *LoginTypesUpdateOK) Code() int {
	return 200
}

func (o *LoginTypesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/LoginTypes/{id}][%d] loginTypesUpdateOK %s", 200, payload)
}

func (o *LoginTypesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/LoginTypes/{id}][%d] loginTypesUpdateOK %s", 200, payload)
}

func (o *LoginTypesUpdateOK) GetPayload() *models.LoginType {
	return o.Payload
}

func (o *LoginTypesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.LoginType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewLoginTypesUpdateDefault creates a LoginTypesUpdateDefault with default headers values
func NewLoginTypesUpdateDefault(code int) *LoginTypesUpdateDefault {
	return &LoginTypesUpdateDefault{
		_statusCode: code,
	}
}

/*
LoginTypesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type LoginTypesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this login types update default response has a 2xx status code
func (o *LoginTypesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this login types update default response has a 3xx status code
func (o *LoginTypesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this login types update default response has a 4xx status code
func (o *LoginTypesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this login types update default response has a 5xx status code
func (o *LoginTypesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this login types update default response a status code equal to that given
func (o *LoginTypesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the login types update default response
func (o *LoginTypesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *LoginTypesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/LoginTypes/{id}][%d] LoginTypes_Update default %s", o._statusCode, payload)
}

func (o *LoginTypesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/LoginTypes/{id}][%d] LoginTypes_Update default %s", o._statusCode, payload)
}

func (o *LoginTypesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *LoginTypesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}