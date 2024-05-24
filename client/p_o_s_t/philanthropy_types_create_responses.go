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

// PhilanthropyTypesCreateReader is a Reader for the PhilanthropyTypesCreate structure.
type PhilanthropyTypesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PhilanthropyTypesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPhilanthropyTypesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPhilanthropyTypesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPhilanthropyTypesCreateOK creates a PhilanthropyTypesCreateOK with default headers values
func NewPhilanthropyTypesCreateOK() *PhilanthropyTypesCreateOK {
	return &PhilanthropyTypesCreateOK{}
}

/*
PhilanthropyTypesCreateOK describes a response with status code 200, with default header values.

OK
*/
type PhilanthropyTypesCreateOK struct {
	Payload *models.PhilanthropyType
}

// IsSuccess returns true when this philanthropy types create o k response has a 2xx status code
func (o *PhilanthropyTypesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this philanthropy types create o k response has a 3xx status code
func (o *PhilanthropyTypesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this philanthropy types create o k response has a 4xx status code
func (o *PhilanthropyTypesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this philanthropy types create o k response has a 5xx status code
func (o *PhilanthropyTypesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this philanthropy types create o k response a status code equal to that given
func (o *PhilanthropyTypesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the philanthropy types create o k response
func (o *PhilanthropyTypesCreateOK) Code() int {
	return 200
}

func (o *PhilanthropyTypesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PhilanthropyTypes][%d] philanthropyTypesCreateOK %s", 200, payload)
}

func (o *PhilanthropyTypesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PhilanthropyTypes][%d] philanthropyTypesCreateOK %s", 200, payload)
}

func (o *PhilanthropyTypesCreateOK) GetPayload() *models.PhilanthropyType {
	return o.Payload
}

func (o *PhilanthropyTypesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PhilanthropyType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPhilanthropyTypesCreateDefault creates a PhilanthropyTypesCreateDefault with default headers values
func NewPhilanthropyTypesCreateDefault(code int) *PhilanthropyTypesCreateDefault {
	return &PhilanthropyTypesCreateDefault{
		_statusCode: code,
	}
}

/*
PhilanthropyTypesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type PhilanthropyTypesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this philanthropy types create default response has a 2xx status code
func (o *PhilanthropyTypesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this philanthropy types create default response has a 3xx status code
func (o *PhilanthropyTypesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this philanthropy types create default response has a 4xx status code
func (o *PhilanthropyTypesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this philanthropy types create default response has a 5xx status code
func (o *PhilanthropyTypesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this philanthropy types create default response a status code equal to that given
func (o *PhilanthropyTypesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the philanthropy types create default response
func (o *PhilanthropyTypesCreateDefault) Code() int {
	return o._statusCode
}

func (o *PhilanthropyTypesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PhilanthropyTypes][%d] PhilanthropyTypes_Create default %s", o._statusCode, payload)
}

func (o *PhilanthropyTypesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PhilanthropyTypes][%d] PhilanthropyTypes_Create default %s", o._statusCode, payload)
}

func (o *PhilanthropyTypesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PhilanthropyTypesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
