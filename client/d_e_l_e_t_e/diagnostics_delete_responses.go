// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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

// DiagnosticsDeleteReader is a Reader for the DiagnosticsDelete structure.
type DiagnosticsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DiagnosticsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDiagnosticsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewDiagnosticsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewDiagnosticsDeleteNoContent creates a DiagnosticsDeleteNoContent with default headers values
func NewDiagnosticsDeleteNoContent() *DiagnosticsDeleteNoContent {
	return &DiagnosticsDeleteNoContent{}
}

/*
DiagnosticsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type DiagnosticsDeleteNoContent struct {
}

// IsSuccess returns true when this diagnostics delete no content response has a 2xx status code
func (o *DiagnosticsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this diagnostics delete no content response has a 3xx status code
func (o *DiagnosticsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this diagnostics delete no content response has a 4xx status code
func (o *DiagnosticsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this diagnostics delete no content response has a 5xx status code
func (o *DiagnosticsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this diagnostics delete no content response a status code equal to that given
func (o *DiagnosticsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the diagnostics delete no content response
func (o *DiagnosticsDeleteNoContent) Code() int {
	return 204
}

func (o *DiagnosticsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /Diagnostics/{diagnosticId}][%d] diagnosticsDeleteNoContent", 204)
}

func (o *DiagnosticsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /Diagnostics/{diagnosticId}][%d] diagnosticsDeleteNoContent", 204)
}

func (o *DiagnosticsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDiagnosticsDeleteDefault creates a DiagnosticsDeleteDefault with default headers values
func NewDiagnosticsDeleteDefault(code int) *DiagnosticsDeleteDefault {
	return &DiagnosticsDeleteDefault{
		_statusCode: code,
	}
}

/*
DiagnosticsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type DiagnosticsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this diagnostics delete default response has a 2xx status code
func (o *DiagnosticsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this diagnostics delete default response has a 3xx status code
func (o *DiagnosticsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this diagnostics delete default response has a 4xx status code
func (o *DiagnosticsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this diagnostics delete default response has a 5xx status code
func (o *DiagnosticsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this diagnostics delete default response a status code equal to that given
func (o *DiagnosticsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the diagnostics delete default response
func (o *DiagnosticsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *DiagnosticsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Diagnostics/{diagnosticId}][%d] Diagnostics_Delete default %s", o._statusCode, payload)
}

func (o *DiagnosticsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Diagnostics/{diagnosticId}][%d] Diagnostics_Delete default %s", o._statusCode, payload)
}

func (o *DiagnosticsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *DiagnosticsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}