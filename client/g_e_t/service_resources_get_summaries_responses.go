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

// ServiceResourcesGetSummariesReader is a Reader for the ServiceResourcesGetSummaries structure.
type ServiceResourcesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ServiceResourcesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewServiceResourcesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewServiceResourcesGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewServiceResourcesGetSummariesOK creates a ServiceResourcesGetSummariesOK with default headers values
func NewServiceResourcesGetSummariesOK() *ServiceResourcesGetSummariesOK {
	return &ServiceResourcesGetSummariesOK{}
}

/*
ServiceResourcesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type ServiceResourcesGetSummariesOK struct {
	Payload []*models.ServiceResourceSummary
}

// IsSuccess returns true when this service resources get summaries o k response has a 2xx status code
func (o *ServiceResourcesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this service resources get summaries o k response has a 3xx status code
func (o *ServiceResourcesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this service resources get summaries o k response has a 4xx status code
func (o *ServiceResourcesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this service resources get summaries o k response has a 5xx status code
func (o *ServiceResourcesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this service resources get summaries o k response a status code equal to that given
func (o *ServiceResourcesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the service resources get summaries o k response
func (o *ServiceResourcesGetSummariesOK) Code() int {
	return 200
}

func (o *ServiceResourcesGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ServiceResources/Summary][%d] serviceResourcesGetSummariesOK %s", 200, payload)
}

func (o *ServiceResourcesGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ServiceResources/Summary][%d] serviceResourcesGetSummariesOK %s", 200, payload)
}

func (o *ServiceResourcesGetSummariesOK) GetPayload() []*models.ServiceResourceSummary {
	return o.Payload
}

func (o *ServiceResourcesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewServiceResourcesGetSummariesDefault creates a ServiceResourcesGetSummariesDefault with default headers values
func NewServiceResourcesGetSummariesDefault(code int) *ServiceResourcesGetSummariesDefault {
	return &ServiceResourcesGetSummariesDefault{
		_statusCode: code,
	}
}

/*
ServiceResourcesGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type ServiceResourcesGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this service resources get summaries default response has a 2xx status code
func (o *ServiceResourcesGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this service resources get summaries default response has a 3xx status code
func (o *ServiceResourcesGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this service resources get summaries default response has a 4xx status code
func (o *ServiceResourcesGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this service resources get summaries default response has a 5xx status code
func (o *ServiceResourcesGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this service resources get summaries default response a status code equal to that given
func (o *ServiceResourcesGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the service resources get summaries default response
func (o *ServiceResourcesGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *ServiceResourcesGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ServiceResources/Summary][%d] ServiceResources_GetSummaries default %s", o._statusCode, payload)
}

func (o *ServiceResourcesGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ServiceResources/Summary][%d] ServiceResources_GetSummaries default %s", o._statusCode, payload)
}

func (o *ServiceResourcesGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ServiceResourcesGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}