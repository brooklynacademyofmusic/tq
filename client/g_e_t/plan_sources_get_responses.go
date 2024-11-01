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

// PlanSourcesGetReader is a Reader for the PlanSourcesGet structure.
type PlanSourcesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PlanSourcesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPlanSourcesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPlanSourcesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPlanSourcesGetOK creates a PlanSourcesGetOK with default headers values
func NewPlanSourcesGetOK() *PlanSourcesGetOK {
	return &PlanSourcesGetOK{}
}

/*
PlanSourcesGetOK describes a response with status code 200, with default header values.

OK
*/
type PlanSourcesGetOK struct {
	Payload *models.PlanSource
}

// IsSuccess returns true when this plan sources get o k response has a 2xx status code
func (o *PlanSourcesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this plan sources get o k response has a 3xx status code
func (o *PlanSourcesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this plan sources get o k response has a 4xx status code
func (o *PlanSourcesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this plan sources get o k response has a 5xx status code
func (o *PlanSourcesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this plan sources get o k response a status code equal to that given
func (o *PlanSourcesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the plan sources get o k response
func (o *PlanSourcesGetOK) Code() int {
	return 200
}

func (o *PlanSourcesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PlanSources/{id}][%d] planSourcesGetOK %s", 200, payload)
}

func (o *PlanSourcesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PlanSources/{id}][%d] planSourcesGetOK %s", 200, payload)
}

func (o *PlanSourcesGetOK) GetPayload() *models.PlanSource {
	return o.Payload
}

func (o *PlanSourcesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PlanSource)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPlanSourcesGetDefault creates a PlanSourcesGetDefault with default headers values
func NewPlanSourcesGetDefault(code int) *PlanSourcesGetDefault {
	return &PlanSourcesGetDefault{
		_statusCode: code,
	}
}

/*
PlanSourcesGetDefault describes a response with status code -1, with default header values.

Error
*/
type PlanSourcesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this plan sources get default response has a 2xx status code
func (o *PlanSourcesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this plan sources get default response has a 3xx status code
func (o *PlanSourcesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this plan sources get default response has a 4xx status code
func (o *PlanSourcesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this plan sources get default response has a 5xx status code
func (o *PlanSourcesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this plan sources get default response a status code equal to that given
func (o *PlanSourcesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the plan sources get default response
func (o *PlanSourcesGetDefault) Code() int {
	return o._statusCode
}

func (o *PlanSourcesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PlanSources/{id}][%d] PlanSources_Get default %s", o._statusCode, payload)
}

func (o *PlanSourcesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PlanSources/{id}][%d] PlanSources_Get default %s", o._statusCode, payload)
}

func (o *PlanSourcesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PlanSourcesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}