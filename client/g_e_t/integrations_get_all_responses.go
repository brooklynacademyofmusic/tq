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

// IntegrationsGetAllReader is a Reader for the IntegrationsGetAll structure.
type IntegrationsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IntegrationsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIntegrationsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewIntegrationsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewIntegrationsGetAllOK creates a IntegrationsGetAllOK with default headers values
func NewIntegrationsGetAllOK() *IntegrationsGetAllOK {
	return &IntegrationsGetAllOK{}
}

/*
IntegrationsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type IntegrationsGetAllOK struct {
	Payload []*models.Integration
}

// IsSuccess returns true when this integrations get all o k response has a 2xx status code
func (o *IntegrationsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this integrations get all o k response has a 3xx status code
func (o *IntegrationsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this integrations get all o k response has a 4xx status code
func (o *IntegrationsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this integrations get all o k response has a 5xx status code
func (o *IntegrationsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this integrations get all o k response a status code equal to that given
func (o *IntegrationsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the integrations get all o k response
func (o *IntegrationsGetAllOK) Code() int {
	return 200
}

func (o *IntegrationsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Integrations][%d] integrationsGetAllOK %s", 200, payload)
}

func (o *IntegrationsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Integrations][%d] integrationsGetAllOK %s", 200, payload)
}

func (o *IntegrationsGetAllOK) GetPayload() []*models.Integration {
	return o.Payload
}

func (o *IntegrationsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIntegrationsGetAllDefault creates a IntegrationsGetAllDefault with default headers values
func NewIntegrationsGetAllDefault(code int) *IntegrationsGetAllDefault {
	return &IntegrationsGetAllDefault{
		_statusCode: code,
	}
}

/*
IntegrationsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type IntegrationsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this integrations get all default response has a 2xx status code
func (o *IntegrationsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this integrations get all default response has a 3xx status code
func (o *IntegrationsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this integrations get all default response has a 4xx status code
func (o *IntegrationsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this integrations get all default response has a 5xx status code
func (o *IntegrationsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this integrations get all default response a status code equal to that given
func (o *IntegrationsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the integrations get all default response
func (o *IntegrationsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *IntegrationsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Integrations][%d] Integrations_GetAll default %s", o._statusCode, payload)
}

func (o *IntegrationsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Integrations][%d] Integrations_GetAll default %s", o._statusCode, payload)
}

func (o *IntegrationsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *IntegrationsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
