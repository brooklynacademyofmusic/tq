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

// ResourcesHasUsagesReader is a Reader for the ResourcesHasUsages structure.
type ResourcesHasUsagesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResourcesHasUsagesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewResourcesHasUsagesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewResourcesHasUsagesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewResourcesHasUsagesOK creates a ResourcesHasUsagesOK with default headers values
func NewResourcesHasUsagesOK() *ResourcesHasUsagesOK {
	return &ResourcesHasUsagesOK{}
}

/*
ResourcesHasUsagesOK describes a response with status code 200, with default header values.

OK
*/
type ResourcesHasUsagesOK struct {
	Payload *models.ResourceUsage
}

// IsSuccess returns true when this resources has usages o k response has a 2xx status code
func (o *ResourcesHasUsagesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this resources has usages o k response has a 3xx status code
func (o *ResourcesHasUsagesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this resources has usages o k response has a 4xx status code
func (o *ResourcesHasUsagesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this resources has usages o k response has a 5xx status code
func (o *ResourcesHasUsagesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this resources has usages o k response a status code equal to that given
func (o *ResourcesHasUsagesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the resources has usages o k response
func (o *ResourcesHasUsagesOK) Code() int {
	return 200
}

func (o *ResourcesHasUsagesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/Resources/{id}/Usages][%d] resourcesHasUsagesOK %s", 200, payload)
}

func (o *ResourcesHasUsagesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/Resources/{id}/Usages][%d] resourcesHasUsagesOK %s", 200, payload)
}

func (o *ResourcesHasUsagesOK) GetPayload() *models.ResourceUsage {
	return o.Payload
}

func (o *ResourcesHasUsagesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResourceUsage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewResourcesHasUsagesDefault creates a ResourcesHasUsagesDefault with default headers values
func NewResourcesHasUsagesDefault(code int) *ResourcesHasUsagesDefault {
	return &ResourcesHasUsagesDefault{
		_statusCode: code,
	}
}

/*
ResourcesHasUsagesDefault describes a response with status code -1, with default header values.

Error
*/
type ResourcesHasUsagesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this resources has usages default response has a 2xx status code
func (o *ResourcesHasUsagesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this resources has usages default response has a 3xx status code
func (o *ResourcesHasUsagesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this resources has usages default response has a 4xx status code
func (o *ResourcesHasUsagesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this resources has usages default response has a 5xx status code
func (o *ResourcesHasUsagesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this resources has usages default response a status code equal to that given
func (o *ResourcesHasUsagesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the resources has usages default response
func (o *ResourcesHasUsagesDefault) Code() int {
	return o._statusCode
}

func (o *ResourcesHasUsagesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/Resources/{id}/Usages][%d] Resources_HasUsages default %s", o._statusCode, payload)
}

func (o *ResourcesHasUsagesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/Resources/{id}/Usages][%d] Resources_HasUsages default %s", o._statusCode, payload)
}

func (o *ResourcesHasUsagesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ResourcesHasUsagesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
