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

// PerformanceTypesCreateReader is a Reader for the PerformanceTypesCreate structure.
type PerformanceTypesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformanceTypesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPerformanceTypesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformanceTypesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformanceTypesCreateOK creates a PerformanceTypesCreateOK with default headers values
func NewPerformanceTypesCreateOK() *PerformanceTypesCreateOK {
	return &PerformanceTypesCreateOK{}
}

/*
PerformanceTypesCreateOK describes a response with status code 200, with default header values.

OK
*/
type PerformanceTypesCreateOK struct {
	Payload *models.PerformanceType
}

// IsSuccess returns true when this performance types create o k response has a 2xx status code
func (o *PerformanceTypesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performance types create o k response has a 3xx status code
func (o *PerformanceTypesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performance types create o k response has a 4xx status code
func (o *PerformanceTypesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this performance types create o k response has a 5xx status code
func (o *PerformanceTypesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this performance types create o k response a status code equal to that given
func (o *PerformanceTypesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the performance types create o k response
func (o *PerformanceTypesCreateOK) Code() int {
	return 200
}

func (o *PerformanceTypesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PerformanceTypes][%d] performanceTypesCreateOK %s", 200, payload)
}

func (o *PerformanceTypesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PerformanceTypes][%d] performanceTypesCreateOK %s", 200, payload)
}

func (o *PerformanceTypesCreateOK) GetPayload() *models.PerformanceType {
	return o.Payload
}

func (o *PerformanceTypesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PerformanceType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPerformanceTypesCreateDefault creates a PerformanceTypesCreateDefault with default headers values
func NewPerformanceTypesCreateDefault(code int) *PerformanceTypesCreateDefault {
	return &PerformanceTypesCreateDefault{
		_statusCode: code,
	}
}

/*
PerformanceTypesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type PerformanceTypesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performance types create default response has a 2xx status code
func (o *PerformanceTypesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performance types create default response has a 3xx status code
func (o *PerformanceTypesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performance types create default response has a 4xx status code
func (o *PerformanceTypesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performance types create default response has a 5xx status code
func (o *PerformanceTypesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performance types create default response a status code equal to that given
func (o *PerformanceTypesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performance types create default response
func (o *PerformanceTypesCreateDefault) Code() int {
	return o._statusCode
}

func (o *PerformanceTypesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PerformanceTypes][%d] PerformanceTypes_Create default %s", o._statusCode, payload)
}

func (o *PerformanceTypesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PerformanceTypes][%d] PerformanceTypes_Create default %s", o._statusCode, payload)
}

func (o *PerformanceTypesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformanceTypesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
