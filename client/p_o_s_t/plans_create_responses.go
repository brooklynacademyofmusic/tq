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

// PlansCreateReader is a Reader for the PlansCreate structure.
type PlansCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PlansCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPlansCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPlansCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPlansCreateOK creates a PlansCreateOK with default headers values
func NewPlansCreateOK() *PlansCreateOK {
	return &PlansCreateOK{}
}

/*
PlansCreateOK describes a response with status code 200, with default header values.

OK
*/
type PlansCreateOK struct {
	Payload *models.Plan
}

// IsSuccess returns true when this plans create o k response has a 2xx status code
func (o *PlansCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this plans create o k response has a 3xx status code
func (o *PlansCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this plans create o k response has a 4xx status code
func (o *PlansCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this plans create o k response has a 5xx status code
func (o *PlansCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this plans create o k response a status code equal to that given
func (o *PlansCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the plans create o k response
func (o *PlansCreateOK) Code() int {
	return 200
}

func (o *PlansCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Finance/Plans][%d] plansCreateOK %s", 200, payload)
}

func (o *PlansCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Finance/Plans][%d] plansCreateOK %s", 200, payload)
}

func (o *PlansCreateOK) GetPayload() *models.Plan {
	return o.Payload
}

func (o *PlansCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Plan)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPlansCreateDefault creates a PlansCreateDefault with default headers values
func NewPlansCreateDefault(code int) *PlansCreateDefault {
	return &PlansCreateDefault{
		_statusCode: code,
	}
}

/*
PlansCreateDefault describes a response with status code -1, with default header values.

Error
*/
type PlansCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this plans create default response has a 2xx status code
func (o *PlansCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this plans create default response has a 3xx status code
func (o *PlansCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this plans create default response has a 4xx status code
func (o *PlansCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this plans create default response has a 5xx status code
func (o *PlansCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this plans create default response a status code equal to that given
func (o *PlansCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the plans create default response
func (o *PlansCreateDefault) Code() int {
	return o._statusCode
}

func (o *PlansCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Finance/Plans][%d] Plans_Create default %s", o._statusCode, payload)
}

func (o *PlansCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Finance/Plans][%d] Plans_Create default %s", o._statusCode, payload)
}

func (o *PlansCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PlansCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}