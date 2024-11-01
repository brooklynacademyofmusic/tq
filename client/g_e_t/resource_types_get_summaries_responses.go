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

// ResourceTypesGetSummariesReader is a Reader for the ResourceTypesGetSummaries structure.
type ResourceTypesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResourceTypesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewResourceTypesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewResourceTypesGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewResourceTypesGetSummariesOK creates a ResourceTypesGetSummariesOK with default headers values
func NewResourceTypesGetSummariesOK() *ResourceTypesGetSummariesOK {
	return &ResourceTypesGetSummariesOK{}
}

/*
ResourceTypesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type ResourceTypesGetSummariesOK struct {
	Payload []*models.ResourceTypeSummary
}

// IsSuccess returns true when this resource types get summaries o k response has a 2xx status code
func (o *ResourceTypesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this resource types get summaries o k response has a 3xx status code
func (o *ResourceTypesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this resource types get summaries o k response has a 4xx status code
func (o *ResourceTypesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this resource types get summaries o k response has a 5xx status code
func (o *ResourceTypesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this resource types get summaries o k response a status code equal to that given
func (o *ResourceTypesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the resource types get summaries o k response
func (o *ResourceTypesGetSummariesOK) Code() int {
	return 200
}

func (o *ResourceTypesGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/ResourceTypes/Summary][%d] resourceTypesGetSummariesOK %s", 200, payload)
}

func (o *ResourceTypesGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/ResourceTypes/Summary][%d] resourceTypesGetSummariesOK %s", 200, payload)
}

func (o *ResourceTypesGetSummariesOK) GetPayload() []*models.ResourceTypeSummary {
	return o.Payload
}

func (o *ResourceTypesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewResourceTypesGetSummariesDefault creates a ResourceTypesGetSummariesDefault with default headers values
func NewResourceTypesGetSummariesDefault(code int) *ResourceTypesGetSummariesDefault {
	return &ResourceTypesGetSummariesDefault{
		_statusCode: code,
	}
}

/*
ResourceTypesGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type ResourceTypesGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this resource types get summaries default response has a 2xx status code
func (o *ResourceTypesGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this resource types get summaries default response has a 3xx status code
func (o *ResourceTypesGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this resource types get summaries default response has a 4xx status code
func (o *ResourceTypesGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this resource types get summaries default response has a 5xx status code
func (o *ResourceTypesGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this resource types get summaries default response a status code equal to that given
func (o *ResourceTypesGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the resource types get summaries default response
func (o *ResourceTypesGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *ResourceTypesGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/ResourceTypes/Summary][%d] ResourceTypes_GetSummaries default %s", o._statusCode, payload)
}

func (o *ResourceTypesGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/ResourceTypes/Summary][%d] ResourceTypes_GetSummaries default %s", o._statusCode, payload)
}

func (o *ResourceTypesGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ResourceTypesGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}