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

// ResourceSchedulesGetAllReader is a Reader for the ResourceSchedulesGetAll structure.
type ResourceSchedulesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResourceSchedulesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewResourceSchedulesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewResourceSchedulesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewResourceSchedulesGetAllOK creates a ResourceSchedulesGetAllOK with default headers values
func NewResourceSchedulesGetAllOK() *ResourceSchedulesGetAllOK {
	return &ResourceSchedulesGetAllOK{}
}

/*
ResourceSchedulesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type ResourceSchedulesGetAllOK struct {
	Payload []*models.ResourceSchedule
}

// IsSuccess returns true when this resource schedules get all o k response has a 2xx status code
func (o *ResourceSchedulesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this resource schedules get all o k response has a 3xx status code
func (o *ResourceSchedulesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this resource schedules get all o k response has a 4xx status code
func (o *ResourceSchedulesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this resource schedules get all o k response has a 5xx status code
func (o *ResourceSchedulesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this resource schedules get all o k response a status code equal to that given
func (o *ResourceSchedulesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the resource schedules get all o k response
func (o *ResourceSchedulesGetAllOK) Code() int {
	return 200
}

func (o *ResourceSchedulesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/ResourceSchedules][%d] resourceSchedulesGetAllOK %s", 200, payload)
}

func (o *ResourceSchedulesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/ResourceSchedules][%d] resourceSchedulesGetAllOK %s", 200, payload)
}

func (o *ResourceSchedulesGetAllOK) GetPayload() []*models.ResourceSchedule {
	return o.Payload
}

func (o *ResourceSchedulesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewResourceSchedulesGetAllDefault creates a ResourceSchedulesGetAllDefault with default headers values
func NewResourceSchedulesGetAllDefault(code int) *ResourceSchedulesGetAllDefault {
	return &ResourceSchedulesGetAllDefault{
		_statusCode: code,
	}
}

/*
ResourceSchedulesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type ResourceSchedulesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this resource schedules get all default response has a 2xx status code
func (o *ResourceSchedulesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this resource schedules get all default response has a 3xx status code
func (o *ResourceSchedulesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this resource schedules get all default response has a 4xx status code
func (o *ResourceSchedulesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this resource schedules get all default response has a 5xx status code
func (o *ResourceSchedulesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this resource schedules get all default response a status code equal to that given
func (o *ResourceSchedulesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the resource schedules get all default response
func (o *ResourceSchedulesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *ResourceSchedulesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/ResourceSchedules][%d] ResourceSchedules_GetAll default %s", o._statusCode, payload)
}

func (o *ResourceSchedulesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/ResourceSchedules][%d] ResourceSchedules_GetAll default %s", o._statusCode, payload)
}

func (o *ResourceSchedulesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ResourceSchedulesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
