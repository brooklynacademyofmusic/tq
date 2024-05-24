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

// PlanWorkersCreateReader is a Reader for the PlanWorkersCreate structure.
type PlanWorkersCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PlanWorkersCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPlanWorkersCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPlanWorkersCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPlanWorkersCreateOK creates a PlanWorkersCreateOK with default headers values
func NewPlanWorkersCreateOK() *PlanWorkersCreateOK {
	return &PlanWorkersCreateOK{}
}

/*
PlanWorkersCreateOK describes a response with status code 200, with default header values.

OK
*/
type PlanWorkersCreateOK struct {
	Payload *models.PlanWorker
}

// IsSuccess returns true when this plan workers create o k response has a 2xx status code
func (o *PlanWorkersCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this plan workers create o k response has a 3xx status code
func (o *PlanWorkersCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this plan workers create o k response has a 4xx status code
func (o *PlanWorkersCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this plan workers create o k response has a 5xx status code
func (o *PlanWorkersCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this plan workers create o k response a status code equal to that given
func (o *PlanWorkersCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the plan workers create o k response
func (o *PlanWorkersCreateOK) Code() int {
	return 200
}

func (o *PlanWorkersCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Finance/PlanWorkers][%d] planWorkersCreateOK %s", 200, payload)
}

func (o *PlanWorkersCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Finance/PlanWorkers][%d] planWorkersCreateOK %s", 200, payload)
}

func (o *PlanWorkersCreateOK) GetPayload() *models.PlanWorker {
	return o.Payload
}

func (o *PlanWorkersCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PlanWorker)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPlanWorkersCreateDefault creates a PlanWorkersCreateDefault with default headers values
func NewPlanWorkersCreateDefault(code int) *PlanWorkersCreateDefault {
	return &PlanWorkersCreateDefault{
		_statusCode: code,
	}
}

/*
PlanWorkersCreateDefault describes a response with status code -1, with default header values.

Error
*/
type PlanWorkersCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this plan workers create default response has a 2xx status code
func (o *PlanWorkersCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this plan workers create default response has a 3xx status code
func (o *PlanWorkersCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this plan workers create default response has a 4xx status code
func (o *PlanWorkersCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this plan workers create default response has a 5xx status code
func (o *PlanWorkersCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this plan workers create default response a status code equal to that given
func (o *PlanWorkersCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the plan workers create default response
func (o *PlanWorkersCreateDefault) Code() int {
	return o._statusCode
}

func (o *PlanWorkersCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Finance/PlanWorkers][%d] PlanWorkers_Create default %s", o._statusCode, payload)
}

func (o *PlanWorkersCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Finance/PlanWorkers][%d] PlanWorkers_Create default %s", o._statusCode, payload)
}

func (o *PlanWorkersCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PlanWorkersCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
