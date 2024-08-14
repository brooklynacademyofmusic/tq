// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

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

// ValidateWebLoginCreateReader is a Reader for the ValidateWebLoginCreate structure.
type ValidateWebLoginCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ValidateWebLoginCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewValidateWebLoginCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewValidateWebLoginCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewValidateWebLoginCreateOK creates a ValidateWebLoginCreateOK with default headers values
func NewValidateWebLoginCreateOK() *ValidateWebLoginCreateOK {
	return &ValidateWebLoginCreateOK{}
}

/*
ValidateWebLoginCreateOK describes a response with status code 200, with default header values.

OK
*/
type ValidateWebLoginCreateOK struct {
	Payload *models.WebLoginValidationResponse
}

// IsSuccess returns true when this validate web login create o k response has a 2xx status code
func (o *ValidateWebLoginCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this validate web login create o k response has a 3xx status code
func (o *ValidateWebLoginCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this validate web login create o k response has a 4xx status code
func (o *ValidateWebLoginCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this validate web login create o k response has a 5xx status code
func (o *ValidateWebLoginCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this validate web login create o k response a status code equal to that given
func (o *ValidateWebLoginCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the validate web login create o k response
func (o *ValidateWebLoginCreateOK) Code() int {
	return 200
}

func (o *ValidateWebLoginCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Security/ValidateWebLogin][%d] validateWebLoginCreateOK %s", 200, payload)
}

func (o *ValidateWebLoginCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Security/ValidateWebLogin][%d] validateWebLoginCreateOK %s", 200, payload)
}

func (o *ValidateWebLoginCreateOK) GetPayload() *models.WebLoginValidationResponse {
	return o.Payload
}

func (o *ValidateWebLoginCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.WebLoginValidationResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewValidateWebLoginCreateDefault creates a ValidateWebLoginCreateDefault with default headers values
func NewValidateWebLoginCreateDefault(code int) *ValidateWebLoginCreateDefault {
	return &ValidateWebLoginCreateDefault{
		_statusCode: code,
	}
}

/*
ValidateWebLoginCreateDefault describes a response with status code -1, with default header values.

Error
*/
type ValidateWebLoginCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this validate web login create default response has a 2xx status code
func (o *ValidateWebLoginCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this validate web login create default response has a 3xx status code
func (o *ValidateWebLoginCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this validate web login create default response has a 4xx status code
func (o *ValidateWebLoginCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this validate web login create default response has a 5xx status code
func (o *ValidateWebLoginCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this validate web login create default response a status code equal to that given
func (o *ValidateWebLoginCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the validate web login create default response
func (o *ValidateWebLoginCreateDefault) Code() int {
	return o._statusCode
}

func (o *ValidateWebLoginCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Security/ValidateWebLogin][%d] ValidateWebLogin_Create default %s", o._statusCode, payload)
}

func (o *ValidateWebLoginCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Security/ValidateWebLogin][%d] ValidateWebLogin_Create default %s", o._statusCode, payload)
}

func (o *ValidateWebLoginCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ValidateWebLoginCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}