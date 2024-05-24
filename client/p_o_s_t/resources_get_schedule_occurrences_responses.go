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

// ResourcesGetScheduleOccurrencesReader is a Reader for the ResourcesGetScheduleOccurrences structure.
type ResourcesGetScheduleOccurrencesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResourcesGetScheduleOccurrencesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewResourcesGetScheduleOccurrencesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewResourcesGetScheduleOccurrencesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewResourcesGetScheduleOccurrencesOK creates a ResourcesGetScheduleOccurrencesOK with default headers values
func NewResourcesGetScheduleOccurrencesOK() *ResourcesGetScheduleOccurrencesOK {
	return &ResourcesGetScheduleOccurrencesOK{}
}

/*
ResourcesGetScheduleOccurrencesOK describes a response with status code 200, with default header values.

OK
*/
type ResourcesGetScheduleOccurrencesOK struct {
	Payload []*models.ScheduleOccurrence
}

// IsSuccess returns true when this resources get schedule occurrences o k response has a 2xx status code
func (o *ResourcesGetScheduleOccurrencesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this resources get schedule occurrences o k response has a 3xx status code
func (o *ResourcesGetScheduleOccurrencesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this resources get schedule occurrences o k response has a 4xx status code
func (o *ResourcesGetScheduleOccurrencesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this resources get schedule occurrences o k response has a 5xx status code
func (o *ResourcesGetScheduleOccurrencesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this resources get schedule occurrences o k response a status code equal to that given
func (o *ResourcesGetScheduleOccurrencesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the resources get schedule occurrences o k response
func (o *ResourcesGetScheduleOccurrencesOK) Code() int {
	return 200
}

func (o *ResourcesGetScheduleOccurrencesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /EventsManagement/Resources/ScheduleOccurrences][%d] resourcesGetScheduleOccurrencesOK %s", 200, payload)
}

func (o *ResourcesGetScheduleOccurrencesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /EventsManagement/Resources/ScheduleOccurrences][%d] resourcesGetScheduleOccurrencesOK %s", 200, payload)
}

func (o *ResourcesGetScheduleOccurrencesOK) GetPayload() []*models.ScheduleOccurrence {
	return o.Payload
}

func (o *ResourcesGetScheduleOccurrencesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewResourcesGetScheduleOccurrencesDefault creates a ResourcesGetScheduleOccurrencesDefault with default headers values
func NewResourcesGetScheduleOccurrencesDefault(code int) *ResourcesGetScheduleOccurrencesDefault {
	return &ResourcesGetScheduleOccurrencesDefault{
		_statusCode: code,
	}
}

/*
ResourcesGetScheduleOccurrencesDefault describes a response with status code -1, with default header values.

Error
*/
type ResourcesGetScheduleOccurrencesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this resources get schedule occurrences default response has a 2xx status code
func (o *ResourcesGetScheduleOccurrencesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this resources get schedule occurrences default response has a 3xx status code
func (o *ResourcesGetScheduleOccurrencesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this resources get schedule occurrences default response has a 4xx status code
func (o *ResourcesGetScheduleOccurrencesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this resources get schedule occurrences default response has a 5xx status code
func (o *ResourcesGetScheduleOccurrencesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this resources get schedule occurrences default response a status code equal to that given
func (o *ResourcesGetScheduleOccurrencesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the resources get schedule occurrences default response
func (o *ResourcesGetScheduleOccurrencesDefault) Code() int {
	return o._statusCode
}

func (o *ResourcesGetScheduleOccurrencesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /EventsManagement/Resources/ScheduleOccurrences][%d] Resources_GetScheduleOccurrences default %s", o._statusCode, payload)
}

func (o *ResourcesGetScheduleOccurrencesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /EventsManagement/Resources/ScheduleOccurrences][%d] Resources_GetScheduleOccurrences default %s", o._statusCode, payload)
}

func (o *ResourcesGetScheduleOccurrencesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ResourcesGetScheduleOccurrencesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
