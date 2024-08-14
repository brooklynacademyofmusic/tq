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

// PerformanceGroupsGetReader is a Reader for the PerformanceGroupsGet structure.
type PerformanceGroupsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformanceGroupsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPerformanceGroupsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformanceGroupsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformanceGroupsGetOK creates a PerformanceGroupsGetOK with default headers values
func NewPerformanceGroupsGetOK() *PerformanceGroupsGetOK {
	return &PerformanceGroupsGetOK{}
}

/*
PerformanceGroupsGetOK describes a response with status code 200, with default header values.

OK
*/
type PerformanceGroupsGetOK struct {
	Payload *models.PerformanceGroup
}

// IsSuccess returns true when this performance groups get o k response has a 2xx status code
func (o *PerformanceGroupsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performance groups get o k response has a 3xx status code
func (o *PerformanceGroupsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performance groups get o k response has a 4xx status code
func (o *PerformanceGroupsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this performance groups get o k response has a 5xx status code
func (o *PerformanceGroupsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this performance groups get o k response a status code equal to that given
func (o *PerformanceGroupsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the performance groups get o k response
func (o *PerformanceGroupsGetOK) Code() int {
	return 200
}

func (o *PerformanceGroupsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PerformanceGroups/{id}][%d] performanceGroupsGetOK %s", 200, payload)
}

func (o *PerformanceGroupsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PerformanceGroups/{id}][%d] performanceGroupsGetOK %s", 200, payload)
}

func (o *PerformanceGroupsGetOK) GetPayload() *models.PerformanceGroup {
	return o.Payload
}

func (o *PerformanceGroupsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PerformanceGroup)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPerformanceGroupsGetDefault creates a PerformanceGroupsGetDefault with default headers values
func NewPerformanceGroupsGetDefault(code int) *PerformanceGroupsGetDefault {
	return &PerformanceGroupsGetDefault{
		_statusCode: code,
	}
}

/*
PerformanceGroupsGetDefault describes a response with status code -1, with default header values.

Error
*/
type PerformanceGroupsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performance groups get default response has a 2xx status code
func (o *PerformanceGroupsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performance groups get default response has a 3xx status code
func (o *PerformanceGroupsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performance groups get default response has a 4xx status code
func (o *PerformanceGroupsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performance groups get default response has a 5xx status code
func (o *PerformanceGroupsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performance groups get default response a status code equal to that given
func (o *PerformanceGroupsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performance groups get default response
func (o *PerformanceGroupsGetDefault) Code() int {
	return o._statusCode
}

func (o *PerformanceGroupsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PerformanceGroups/{id}][%d] PerformanceGroups_Get default %s", o._statusCode, payload)
}

func (o *PerformanceGroupsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PerformanceGroups/{id}][%d] PerformanceGroups_Get default %s", o._statusCode, payload)
}

func (o *PerformanceGroupsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformanceGroupsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}