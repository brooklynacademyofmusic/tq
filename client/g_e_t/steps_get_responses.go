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

// StepsGetReader is a Reader for the StepsGet structure.
type StepsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *StepsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewStepsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewStepsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewStepsGetOK creates a StepsGetOK with default headers values
func NewStepsGetOK() *StepsGetOK {
	return &StepsGetOK{}
}

/*
StepsGetOK describes a response with status code 200, with default header values.

OK
*/
type StepsGetOK struct {
	Payload *models.Step
}

// IsSuccess returns true when this steps get o k response has a 2xx status code
func (o *StepsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this steps get o k response has a 3xx status code
func (o *StepsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this steps get o k response has a 4xx status code
func (o *StepsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this steps get o k response has a 5xx status code
func (o *StepsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this steps get o k response a status code equal to that given
func (o *StepsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the steps get o k response
func (o *StepsGetOK) Code() int {
	return 200
}

func (o *StepsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Steps/{stepId}][%d] stepsGetOK %s", 200, payload)
}

func (o *StepsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Steps/{stepId}][%d] stepsGetOK %s", 200, payload)
}

func (o *StepsGetOK) GetPayload() *models.Step {
	return o.Payload
}

func (o *StepsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Step)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewStepsGetDefault creates a StepsGetDefault with default headers values
func NewStepsGetDefault(code int) *StepsGetDefault {
	return &StepsGetDefault{
		_statusCode: code,
	}
}

/*
StepsGetDefault describes a response with status code -1, with default header values.

Error
*/
type StepsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this steps get default response has a 2xx status code
func (o *StepsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this steps get default response has a 3xx status code
func (o *StepsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this steps get default response has a 4xx status code
func (o *StepsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this steps get default response has a 5xx status code
func (o *StepsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this steps get default response a status code equal to that given
func (o *StepsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the steps get default response
func (o *StepsGetDefault) Code() int {
	return o._statusCode
}

func (o *StepsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Steps/{stepId}][%d] Steps_Get default %s", o._statusCode, payload)
}

func (o *StepsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Steps/{stepId}][%d] Steps_Get default %s", o._statusCode, payload)
}

func (o *StepsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *StepsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}