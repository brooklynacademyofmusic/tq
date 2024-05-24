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

// PlanWorkersUpdateReader is a Reader for the PlanWorkersUpdate structure.
type PlanWorkersUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PlanWorkersUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPlanWorkersUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPlanWorkersUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPlanWorkersUpdateOK creates a PlanWorkersUpdateOK with default headers values
func NewPlanWorkersUpdateOK() *PlanWorkersUpdateOK {
	return &PlanWorkersUpdateOK{}
}

/*
PlanWorkersUpdateOK describes a response with status code 200, with default header values.

OK
*/
type PlanWorkersUpdateOK struct {
	Payload *models.PlanWorker
}

// IsSuccess returns true when this plan workers update o k response has a 2xx status code
func (o *PlanWorkersUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this plan workers update o k response has a 3xx status code
func (o *PlanWorkersUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this plan workers update o k response has a 4xx status code
func (o *PlanWorkersUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this plan workers update o k response has a 5xx status code
func (o *PlanWorkersUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this plan workers update o k response a status code equal to that given
func (o *PlanWorkersUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the plan workers update o k response
func (o *PlanWorkersUpdateOK) Code() int {
	return 200
}

func (o *PlanWorkersUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Finance/PlanWorkers/{planWorkerId}][%d] planWorkersUpdateOK %s", 200, payload)
}

func (o *PlanWorkersUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Finance/PlanWorkers/{planWorkerId}][%d] planWorkersUpdateOK %s", 200, payload)
}

func (o *PlanWorkersUpdateOK) GetPayload() *models.PlanWorker {
	return o.Payload
}

func (o *PlanWorkersUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PlanWorker)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPlanWorkersUpdateDefault creates a PlanWorkersUpdateDefault with default headers values
func NewPlanWorkersUpdateDefault(code int) *PlanWorkersUpdateDefault {
	return &PlanWorkersUpdateDefault{
		_statusCode: code,
	}
}

/*
PlanWorkersUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type PlanWorkersUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this plan workers update default response has a 2xx status code
func (o *PlanWorkersUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this plan workers update default response has a 3xx status code
func (o *PlanWorkersUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this plan workers update default response has a 4xx status code
func (o *PlanWorkersUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this plan workers update default response has a 5xx status code
func (o *PlanWorkersUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this plan workers update default response a status code equal to that given
func (o *PlanWorkersUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the plan workers update default response
func (o *PlanWorkersUpdateDefault) Code() int {
	return o._statusCode
}

func (o *PlanWorkersUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Finance/PlanWorkers/{planWorkerId}][%d] PlanWorkers_Update default %s", o._statusCode, payload)
}

func (o *PlanWorkersUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Finance/PlanWorkers/{planWorkerId}][%d] PlanWorkers_Update default %s", o._statusCode, payload)
}

func (o *PlanWorkersUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PlanWorkersUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
