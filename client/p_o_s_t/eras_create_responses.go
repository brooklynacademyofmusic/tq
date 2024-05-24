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

// ErasCreateReader is a Reader for the ErasCreate structure.
type ErasCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ErasCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewErasCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewErasCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewErasCreateOK creates a ErasCreateOK with default headers values
func NewErasCreateOK() *ErasCreateOK {
	return &ErasCreateOK{}
}

/*
ErasCreateOK describes a response with status code 200, with default header values.

OK
*/
type ErasCreateOK struct {
	Payload *models.Era
}

// IsSuccess returns true when this eras create o k response has a 2xx status code
func (o *ErasCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this eras create o k response has a 3xx status code
func (o *ErasCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this eras create o k response has a 4xx status code
func (o *ErasCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this eras create o k response has a 5xx status code
func (o *ErasCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this eras create o k response a status code equal to that given
func (o *ErasCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the eras create o k response
func (o *ErasCreateOK) Code() int {
	return 200
}

func (o *ErasCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Eras][%d] erasCreateOK %s", 200, payload)
}

func (o *ErasCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Eras][%d] erasCreateOK %s", 200, payload)
}

func (o *ErasCreateOK) GetPayload() *models.Era {
	return o.Payload
}

func (o *ErasCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Era)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewErasCreateDefault creates a ErasCreateDefault with default headers values
func NewErasCreateDefault(code int) *ErasCreateDefault {
	return &ErasCreateDefault{
		_statusCode: code,
	}
}

/*
ErasCreateDefault describes a response with status code -1, with default header values.

Error
*/
type ErasCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this eras create default response has a 2xx status code
func (o *ErasCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this eras create default response has a 3xx status code
func (o *ErasCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this eras create default response has a 4xx status code
func (o *ErasCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this eras create default response has a 5xx status code
func (o *ErasCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this eras create default response a status code equal to that given
func (o *ErasCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the eras create default response
func (o *ErasCreateDefault) Code() int {
	return o._statusCode
}

func (o *ErasCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Eras][%d] Eras_Create default %s", o._statusCode, payload)
}

func (o *ErasCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Eras][%d] Eras_Create default %s", o._statusCode, payload)
}

func (o *ErasCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ErasCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
