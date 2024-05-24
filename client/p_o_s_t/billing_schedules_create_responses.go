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

// BillingSchedulesCreateReader is a Reader for the BillingSchedulesCreate structure.
type BillingSchedulesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BillingSchedulesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewBillingSchedulesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewBillingSchedulesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewBillingSchedulesCreateOK creates a BillingSchedulesCreateOK with default headers values
func NewBillingSchedulesCreateOK() *BillingSchedulesCreateOK {
	return &BillingSchedulesCreateOK{}
}

/*
BillingSchedulesCreateOK describes a response with status code 200, with default header values.

OK
*/
type BillingSchedulesCreateOK struct {
	Payload *models.BillingSchedule
}

// IsSuccess returns true when this billing schedules create o k response has a 2xx status code
func (o *BillingSchedulesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this billing schedules create o k response has a 3xx status code
func (o *BillingSchedulesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this billing schedules create o k response has a 4xx status code
func (o *BillingSchedulesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this billing schedules create o k response has a 5xx status code
func (o *BillingSchedulesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this billing schedules create o k response a status code equal to that given
func (o *BillingSchedulesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the billing schedules create o k response
func (o *BillingSchedulesCreateOK) Code() int {
	return 200
}

func (o *BillingSchedulesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/BillingSchedules][%d] billingSchedulesCreateOK %s", 200, payload)
}

func (o *BillingSchedulesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/BillingSchedules][%d] billingSchedulesCreateOK %s", 200, payload)
}

func (o *BillingSchedulesCreateOK) GetPayload() *models.BillingSchedule {
	return o.Payload
}

func (o *BillingSchedulesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BillingSchedule)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBillingSchedulesCreateDefault creates a BillingSchedulesCreateDefault with default headers values
func NewBillingSchedulesCreateDefault(code int) *BillingSchedulesCreateDefault {
	return &BillingSchedulesCreateDefault{
		_statusCode: code,
	}
}

/*
BillingSchedulesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type BillingSchedulesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this billing schedules create default response has a 2xx status code
func (o *BillingSchedulesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this billing schedules create default response has a 3xx status code
func (o *BillingSchedulesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this billing schedules create default response has a 4xx status code
func (o *BillingSchedulesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this billing schedules create default response has a 5xx status code
func (o *BillingSchedulesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this billing schedules create default response a status code equal to that given
func (o *BillingSchedulesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the billing schedules create default response
func (o *BillingSchedulesCreateDefault) Code() int {
	return o._statusCode
}

func (o *BillingSchedulesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/BillingSchedules][%d] BillingSchedules_Create default %s", o._statusCode, payload)
}

func (o *BillingSchedulesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/BillingSchedules][%d] BillingSchedules_Create default %s", o._statusCode, payload)
}

func (o *BillingSchedulesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *BillingSchedulesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
