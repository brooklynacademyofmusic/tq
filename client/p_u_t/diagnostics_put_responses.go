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

// DiagnosticsPutReader is a Reader for the DiagnosticsPut structure.
type DiagnosticsPutReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DiagnosticsPutReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDiagnosticsPutOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewDiagnosticsPutDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewDiagnosticsPutOK creates a DiagnosticsPutOK with default headers values
func NewDiagnosticsPutOK() *DiagnosticsPutOK {
	return &DiagnosticsPutOK{}
}

/*
DiagnosticsPutOK describes a response with status code 200, with default header values.

OK
*/
type DiagnosticsPutOK struct {
	Payload *models.Diagnostic
}

// IsSuccess returns true when this diagnostics put o k response has a 2xx status code
func (o *DiagnosticsPutOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this diagnostics put o k response has a 3xx status code
func (o *DiagnosticsPutOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this diagnostics put o k response has a 4xx status code
func (o *DiagnosticsPutOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this diagnostics put o k response has a 5xx status code
func (o *DiagnosticsPutOK) IsServerError() bool {
	return false
}

// IsCode returns true when this diagnostics put o k response a status code equal to that given
func (o *DiagnosticsPutOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the diagnostics put o k response
func (o *DiagnosticsPutOK) Code() int {
	return 200
}

func (o *DiagnosticsPutOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Diagnostics/{diagnosticId}][%d] diagnosticsPutOK %s", 200, payload)
}

func (o *DiagnosticsPutOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Diagnostics/{diagnosticId}][%d] diagnosticsPutOK %s", 200, payload)
}

func (o *DiagnosticsPutOK) GetPayload() *models.Diagnostic {
	return o.Payload
}

func (o *DiagnosticsPutOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Diagnostic)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDiagnosticsPutDefault creates a DiagnosticsPutDefault with default headers values
func NewDiagnosticsPutDefault(code int) *DiagnosticsPutDefault {
	return &DiagnosticsPutDefault{
		_statusCode: code,
	}
}

/*
DiagnosticsPutDefault describes a response with status code -1, with default header values.

Error
*/
type DiagnosticsPutDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this diagnostics put default response has a 2xx status code
func (o *DiagnosticsPutDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this diagnostics put default response has a 3xx status code
func (o *DiagnosticsPutDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this diagnostics put default response has a 4xx status code
func (o *DiagnosticsPutDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this diagnostics put default response has a 5xx status code
func (o *DiagnosticsPutDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this diagnostics put default response a status code equal to that given
func (o *DiagnosticsPutDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the diagnostics put default response
func (o *DiagnosticsPutDefault) Code() int {
	return o._statusCode
}

func (o *DiagnosticsPutDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Diagnostics/{diagnosticId}][%d] Diagnostics_Put default %s", o._statusCode, payload)
}

func (o *DiagnosticsPutDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Diagnostics/{diagnosticId}][%d] Diagnostics_Put default %s", o._statusCode, payload)
}

func (o *DiagnosticsPutDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *DiagnosticsPutDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}