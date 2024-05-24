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

// PlanPrioritiesCreateReader is a Reader for the PlanPrioritiesCreate structure.
type PlanPrioritiesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PlanPrioritiesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPlanPrioritiesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPlanPrioritiesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPlanPrioritiesCreateOK creates a PlanPrioritiesCreateOK with default headers values
func NewPlanPrioritiesCreateOK() *PlanPrioritiesCreateOK {
	return &PlanPrioritiesCreateOK{}
}

/*
PlanPrioritiesCreateOK describes a response with status code 200, with default header values.

OK
*/
type PlanPrioritiesCreateOK struct {
	Payload *models.PlanPriority
}

// IsSuccess returns true when this plan priorities create o k response has a 2xx status code
func (o *PlanPrioritiesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this plan priorities create o k response has a 3xx status code
func (o *PlanPrioritiesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this plan priorities create o k response has a 4xx status code
func (o *PlanPrioritiesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this plan priorities create o k response has a 5xx status code
func (o *PlanPrioritiesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this plan priorities create o k response a status code equal to that given
func (o *PlanPrioritiesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the plan priorities create o k response
func (o *PlanPrioritiesCreateOK) Code() int {
	return 200
}

func (o *PlanPrioritiesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PlanPriorities][%d] planPrioritiesCreateOK %s", 200, payload)
}

func (o *PlanPrioritiesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PlanPriorities][%d] planPrioritiesCreateOK %s", 200, payload)
}

func (o *PlanPrioritiesCreateOK) GetPayload() *models.PlanPriority {
	return o.Payload
}

func (o *PlanPrioritiesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PlanPriority)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPlanPrioritiesCreateDefault creates a PlanPrioritiesCreateDefault with default headers values
func NewPlanPrioritiesCreateDefault(code int) *PlanPrioritiesCreateDefault {
	return &PlanPrioritiesCreateDefault{
		_statusCode: code,
	}
}

/*
PlanPrioritiesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type PlanPrioritiesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this plan priorities create default response has a 2xx status code
func (o *PlanPrioritiesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this plan priorities create default response has a 3xx status code
func (o *PlanPrioritiesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this plan priorities create default response has a 4xx status code
func (o *PlanPrioritiesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this plan priorities create default response has a 5xx status code
func (o *PlanPrioritiesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this plan priorities create default response a status code equal to that given
func (o *PlanPrioritiesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the plan priorities create default response
func (o *PlanPrioritiesCreateDefault) Code() int {
	return o._statusCode
}

func (o *PlanPrioritiesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PlanPriorities][%d] PlanPriorities_Create default %s", o._statusCode, payload)
}

func (o *PlanPrioritiesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PlanPriorities][%d] PlanPriorities_Create default %s", o._statusCode, payload)
}

func (o *PlanPrioritiesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PlanPrioritiesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
