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

// ResourcesFindAvailableResourcesReader is a Reader for the ResourcesFindAvailableResources structure.
type ResourcesFindAvailableResourcesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResourcesFindAvailableResourcesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewResourcesFindAvailableResourcesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewResourcesFindAvailableResourcesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewResourcesFindAvailableResourcesOK creates a ResourcesFindAvailableResourcesOK with default headers values
func NewResourcesFindAvailableResourcesOK() *ResourcesFindAvailableResourcesOK {
	return &ResourcesFindAvailableResourcesOK{}
}

/*
ResourcesFindAvailableResourcesOK describes a response with status code 200, with default header values.

OK
*/
type ResourcesFindAvailableResourcesOK struct {
	Payload []*models.ResourceSearchSummary
}

// IsSuccess returns true when this resources find available resources o k response has a 2xx status code
func (o *ResourcesFindAvailableResourcesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this resources find available resources o k response has a 3xx status code
func (o *ResourcesFindAvailableResourcesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this resources find available resources o k response has a 4xx status code
func (o *ResourcesFindAvailableResourcesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this resources find available resources o k response has a 5xx status code
func (o *ResourcesFindAvailableResourcesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this resources find available resources o k response a status code equal to that given
func (o *ResourcesFindAvailableResourcesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the resources find available resources o k response
func (o *ResourcesFindAvailableResourcesOK) Code() int {
	return 200
}

func (o *ResourcesFindAvailableResourcesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /EventsManagement/Resources/FindAvailable][%d] resourcesFindAvailableResourcesOK %s", 200, payload)
}

func (o *ResourcesFindAvailableResourcesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /EventsManagement/Resources/FindAvailable][%d] resourcesFindAvailableResourcesOK %s", 200, payload)
}

func (o *ResourcesFindAvailableResourcesOK) GetPayload() []*models.ResourceSearchSummary {
	return o.Payload
}

func (o *ResourcesFindAvailableResourcesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewResourcesFindAvailableResourcesDefault creates a ResourcesFindAvailableResourcesDefault with default headers values
func NewResourcesFindAvailableResourcesDefault(code int) *ResourcesFindAvailableResourcesDefault {
	return &ResourcesFindAvailableResourcesDefault{
		_statusCode: code,
	}
}

/*
ResourcesFindAvailableResourcesDefault describes a response with status code -1, with default header values.

Error
*/
type ResourcesFindAvailableResourcesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this resources find available resources default response has a 2xx status code
func (o *ResourcesFindAvailableResourcesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this resources find available resources default response has a 3xx status code
func (o *ResourcesFindAvailableResourcesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this resources find available resources default response has a 4xx status code
func (o *ResourcesFindAvailableResourcesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this resources find available resources default response has a 5xx status code
func (o *ResourcesFindAvailableResourcesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this resources find available resources default response a status code equal to that given
func (o *ResourcesFindAvailableResourcesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the resources find available resources default response
func (o *ResourcesFindAvailableResourcesDefault) Code() int {
	return o._statusCode
}

func (o *ResourcesFindAvailableResourcesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /EventsManagement/Resources/FindAvailable][%d] Resources_FindAvailableResources default %s", o._statusCode, payload)
}

func (o *ResourcesFindAvailableResourcesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /EventsManagement/Resources/FindAvailable][%d] Resources_FindAvailableResources default %s", o._statusCode, payload)
}

func (o *ResourcesFindAvailableResourcesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ResourcesFindAvailableResourcesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}