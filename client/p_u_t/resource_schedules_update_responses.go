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

// ResourceSchedulesUpdateReader is a Reader for the ResourceSchedulesUpdate structure.
type ResourceSchedulesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResourceSchedulesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewResourceSchedulesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewResourceSchedulesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewResourceSchedulesUpdateOK creates a ResourceSchedulesUpdateOK with default headers values
func NewResourceSchedulesUpdateOK() *ResourceSchedulesUpdateOK {
	return &ResourceSchedulesUpdateOK{}
}

/*
ResourceSchedulesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type ResourceSchedulesUpdateOK struct {
	Payload *models.ResourceSchedule
}

// IsSuccess returns true when this resource schedules update o k response has a 2xx status code
func (o *ResourceSchedulesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this resource schedules update o k response has a 3xx status code
func (o *ResourceSchedulesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this resource schedules update o k response has a 4xx status code
func (o *ResourceSchedulesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this resource schedules update o k response has a 5xx status code
func (o *ResourceSchedulesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this resource schedules update o k response a status code equal to that given
func (o *ResourceSchedulesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the resource schedules update o k response
func (o *ResourceSchedulesUpdateOK) Code() int {
	return 200
}

func (o *ResourceSchedulesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /EventsManagement/ResourceSchedules/{resourceScheduleId}][%d] resourceSchedulesUpdateOK %s", 200, payload)
}

func (o *ResourceSchedulesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /EventsManagement/ResourceSchedules/{resourceScheduleId}][%d] resourceSchedulesUpdateOK %s", 200, payload)
}

func (o *ResourceSchedulesUpdateOK) GetPayload() *models.ResourceSchedule {
	return o.Payload
}

func (o *ResourceSchedulesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResourceSchedule)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewResourceSchedulesUpdateDefault creates a ResourceSchedulesUpdateDefault with default headers values
func NewResourceSchedulesUpdateDefault(code int) *ResourceSchedulesUpdateDefault {
	return &ResourceSchedulesUpdateDefault{
		_statusCode: code,
	}
}

/*
ResourceSchedulesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type ResourceSchedulesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this resource schedules update default response has a 2xx status code
func (o *ResourceSchedulesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this resource schedules update default response has a 3xx status code
func (o *ResourceSchedulesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this resource schedules update default response has a 4xx status code
func (o *ResourceSchedulesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this resource schedules update default response has a 5xx status code
func (o *ResourceSchedulesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this resource schedules update default response a status code equal to that given
func (o *ResourceSchedulesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the resource schedules update default response
func (o *ResourceSchedulesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *ResourceSchedulesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /EventsManagement/ResourceSchedules/{resourceScheduleId}][%d] ResourceSchedules_Update default %s", o._statusCode, payload)
}

func (o *ResourceSchedulesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /EventsManagement/ResourceSchedules/{resourceScheduleId}][%d] ResourceSchedules_Update default %s", o._statusCode, payload)
}

func (o *ResourceSchedulesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ResourceSchedulesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
