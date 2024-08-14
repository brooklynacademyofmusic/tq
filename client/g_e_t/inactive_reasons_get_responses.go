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

// InactiveReasonsGetReader is a Reader for the InactiveReasonsGet structure.
type InactiveReasonsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *InactiveReasonsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewInactiveReasonsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewInactiveReasonsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewInactiveReasonsGetOK creates a InactiveReasonsGetOK with default headers values
func NewInactiveReasonsGetOK() *InactiveReasonsGetOK {
	return &InactiveReasonsGetOK{}
}

/*
InactiveReasonsGetOK describes a response with status code 200, with default header values.

OK
*/
type InactiveReasonsGetOK struct {
	Payload *models.InactiveReason
}

// IsSuccess returns true when this inactive reasons get o k response has a 2xx status code
func (o *InactiveReasonsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this inactive reasons get o k response has a 3xx status code
func (o *InactiveReasonsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this inactive reasons get o k response has a 4xx status code
func (o *InactiveReasonsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this inactive reasons get o k response has a 5xx status code
func (o *InactiveReasonsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this inactive reasons get o k response a status code equal to that given
func (o *InactiveReasonsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the inactive reasons get o k response
func (o *InactiveReasonsGetOK) Code() int {
	return 200
}

func (o *InactiveReasonsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/InactiveReasons/{id}][%d] inactiveReasonsGetOK %s", 200, payload)
}

func (o *InactiveReasonsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/InactiveReasons/{id}][%d] inactiveReasonsGetOK %s", 200, payload)
}

func (o *InactiveReasonsGetOK) GetPayload() *models.InactiveReason {
	return o.Payload
}

func (o *InactiveReasonsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.InactiveReason)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewInactiveReasonsGetDefault creates a InactiveReasonsGetDefault with default headers values
func NewInactiveReasonsGetDefault(code int) *InactiveReasonsGetDefault {
	return &InactiveReasonsGetDefault{
		_statusCode: code,
	}
}

/*
InactiveReasonsGetDefault describes a response with status code -1, with default header values.

Error
*/
type InactiveReasonsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this inactive reasons get default response has a 2xx status code
func (o *InactiveReasonsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this inactive reasons get default response has a 3xx status code
func (o *InactiveReasonsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this inactive reasons get default response has a 4xx status code
func (o *InactiveReasonsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this inactive reasons get default response has a 5xx status code
func (o *InactiveReasonsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this inactive reasons get default response a status code equal to that given
func (o *InactiveReasonsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the inactive reasons get default response
func (o *InactiveReasonsGetDefault) Code() int {
	return o._statusCode
}

func (o *InactiveReasonsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/InactiveReasons/{id}][%d] InactiveReasons_Get default %s", o._statusCode, payload)
}

func (o *InactiveReasonsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/InactiveReasons/{id}][%d] InactiveReasons_Get default %s", o._statusCode, payload)
}

func (o *InactiveReasonsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *InactiveReasonsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}