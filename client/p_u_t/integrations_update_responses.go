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

// IntegrationsUpdateReader is a Reader for the IntegrationsUpdate structure.
type IntegrationsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IntegrationsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIntegrationsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewIntegrationsUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewIntegrationsUpdateOK creates a IntegrationsUpdateOK with default headers values
func NewIntegrationsUpdateOK() *IntegrationsUpdateOK {
	return &IntegrationsUpdateOK{}
}

/*
IntegrationsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type IntegrationsUpdateOK struct {
	Payload *models.Integration
}

// IsSuccess returns true when this integrations update o k response has a 2xx status code
func (o *IntegrationsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this integrations update o k response has a 3xx status code
func (o *IntegrationsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this integrations update o k response has a 4xx status code
func (o *IntegrationsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this integrations update o k response has a 5xx status code
func (o *IntegrationsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this integrations update o k response a status code equal to that given
func (o *IntegrationsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the integrations update o k response
func (o *IntegrationsUpdateOK) Code() int {
	return 200
}

func (o *IntegrationsUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Integrations/{id}][%d] integrationsUpdateOK %s", 200, payload)
}

func (o *IntegrationsUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Integrations/{id}][%d] integrationsUpdateOK %s", 200, payload)
}

func (o *IntegrationsUpdateOK) GetPayload() *models.Integration {
	return o.Payload
}

func (o *IntegrationsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Integration)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIntegrationsUpdateDefault creates a IntegrationsUpdateDefault with default headers values
func NewIntegrationsUpdateDefault(code int) *IntegrationsUpdateDefault {
	return &IntegrationsUpdateDefault{
		_statusCode: code,
	}
}

/*
IntegrationsUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type IntegrationsUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this integrations update default response has a 2xx status code
func (o *IntegrationsUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this integrations update default response has a 3xx status code
func (o *IntegrationsUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this integrations update default response has a 4xx status code
func (o *IntegrationsUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this integrations update default response has a 5xx status code
func (o *IntegrationsUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this integrations update default response a status code equal to that given
func (o *IntegrationsUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the integrations update default response
func (o *IntegrationsUpdateDefault) Code() int {
	return o._statusCode
}

func (o *IntegrationsUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Integrations/{id}][%d] Integrations_Update default %s", o._statusCode, payload)
}

func (o *IntegrationsUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Integrations/{id}][%d] Integrations_Update default %s", o._statusCode, payload)
}

func (o *IntegrationsUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *IntegrationsUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
