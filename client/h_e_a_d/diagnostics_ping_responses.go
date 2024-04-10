// Code generated by go-swagger; DO NOT EDIT.

package h_e_a_d

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// DiagnosticsPingReader is a Reader for the DiagnosticsPing structure.
type DiagnosticsPingReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DiagnosticsPingReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDiagnosticsPingNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[HEAD /Diagnostics/Ping] Diagnostics_Ping", response, response.Code())
	}
}

// NewDiagnosticsPingNoContent creates a DiagnosticsPingNoContent with default headers values
func NewDiagnosticsPingNoContent() *DiagnosticsPingNoContent {
	return &DiagnosticsPingNoContent{}
}

/*
DiagnosticsPingNoContent describes a response with status code 204, with default header values.

No Content
*/
type DiagnosticsPingNoContent struct {
}

// IsSuccess returns true when this diagnostics ping no content response has a 2xx status code
func (o *DiagnosticsPingNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this diagnostics ping no content response has a 3xx status code
func (o *DiagnosticsPingNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this diagnostics ping no content response has a 4xx status code
func (o *DiagnosticsPingNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this diagnostics ping no content response has a 5xx status code
func (o *DiagnosticsPingNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this diagnostics ping no content response a status code equal to that given
func (o *DiagnosticsPingNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the diagnostics ping no content response
func (o *DiagnosticsPingNoContent) Code() int {
	return 204
}

func (o *DiagnosticsPingNoContent) Error() string {
	return fmt.Sprintf("[HEAD /Diagnostics/Ping][%d] diagnosticsPingNoContent ", 204)
}

func (o *DiagnosticsPingNoContent) String() string {
	return fmt.Sprintf("[HEAD /Diagnostics/Ping][%d] diagnosticsPingNoContent ", 204)
}

func (o *DiagnosticsPingNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}