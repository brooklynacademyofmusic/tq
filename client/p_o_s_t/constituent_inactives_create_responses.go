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

// ConstituentInactivesCreateReader is a Reader for the ConstituentInactivesCreate structure.
type ConstituentInactivesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ConstituentInactivesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewConstituentInactivesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewConstituentInactivesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewConstituentInactivesCreateOK creates a ConstituentInactivesCreateOK with default headers values
func NewConstituentInactivesCreateOK() *ConstituentInactivesCreateOK {
	return &ConstituentInactivesCreateOK{}
}

/*
ConstituentInactivesCreateOK describes a response with status code 200, with default header values.

OK
*/
type ConstituentInactivesCreateOK struct {
	Payload *models.ConstituentInactive
}

// IsSuccess returns true when this constituent inactives create o k response has a 2xx status code
func (o *ConstituentInactivesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this constituent inactives create o k response has a 3xx status code
func (o *ConstituentInactivesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this constituent inactives create o k response has a 4xx status code
func (o *ConstituentInactivesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this constituent inactives create o k response has a 5xx status code
func (o *ConstituentInactivesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this constituent inactives create o k response a status code equal to that given
func (o *ConstituentInactivesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the constituent inactives create o k response
func (o *ConstituentInactivesCreateOK) Code() int {
	return 200
}

func (o *ConstituentInactivesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ConstituentInactives][%d] constituentInactivesCreateOK %s", 200, payload)
}

func (o *ConstituentInactivesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ConstituentInactives][%d] constituentInactivesCreateOK %s", 200, payload)
}

func (o *ConstituentInactivesCreateOK) GetPayload() *models.ConstituentInactive {
	return o.Payload
}

func (o *ConstituentInactivesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConstituentInactive)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConstituentInactivesCreateDefault creates a ConstituentInactivesCreateDefault with default headers values
func NewConstituentInactivesCreateDefault(code int) *ConstituentInactivesCreateDefault {
	return &ConstituentInactivesCreateDefault{
		_statusCode: code,
	}
}

/*
ConstituentInactivesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type ConstituentInactivesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this constituent inactives create default response has a 2xx status code
func (o *ConstituentInactivesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this constituent inactives create default response has a 3xx status code
func (o *ConstituentInactivesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this constituent inactives create default response has a 4xx status code
func (o *ConstituentInactivesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this constituent inactives create default response has a 5xx status code
func (o *ConstituentInactivesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this constituent inactives create default response a status code equal to that given
func (o *ConstituentInactivesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the constituent inactives create default response
func (o *ConstituentInactivesCreateDefault) Code() int {
	return o._statusCode
}

func (o *ConstituentInactivesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ConstituentInactives][%d] ConstituentInactives_Create default %s", o._statusCode, payload)
}

func (o *ConstituentInactivesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ConstituentInactives][%d] ConstituentInactives_Create default %s", o._statusCode, payload)
}

func (o *ConstituentInactivesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ConstituentInactivesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}