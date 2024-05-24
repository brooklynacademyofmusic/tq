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

// DiagnosticsGetSeatServerStatusReader is a Reader for the DiagnosticsGetSeatServerStatus structure.
type DiagnosticsGetSeatServerStatusReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DiagnosticsGetSeatServerStatusReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDiagnosticsGetSeatServerStatusOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewDiagnosticsGetSeatServerStatusDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewDiagnosticsGetSeatServerStatusOK creates a DiagnosticsGetSeatServerStatusOK with default headers values
func NewDiagnosticsGetSeatServerStatusOK() *DiagnosticsGetSeatServerStatusOK {
	return &DiagnosticsGetSeatServerStatusOK{}
}

/*
DiagnosticsGetSeatServerStatusOK describes a response with status code 200, with default header values.

OK
*/
type DiagnosticsGetSeatServerStatusOK struct {
	Payload *models.SeatServerStatus
}

// IsSuccess returns true when this diagnostics get seat server status o k response has a 2xx status code
func (o *DiagnosticsGetSeatServerStatusOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this diagnostics get seat server status o k response has a 3xx status code
func (o *DiagnosticsGetSeatServerStatusOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this diagnostics get seat server status o k response has a 4xx status code
func (o *DiagnosticsGetSeatServerStatusOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this diagnostics get seat server status o k response has a 5xx status code
func (o *DiagnosticsGetSeatServerStatusOK) IsServerError() bool {
	return false
}

// IsCode returns true when this diagnostics get seat server status o k response a status code equal to that given
func (o *DiagnosticsGetSeatServerStatusOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the diagnostics get seat server status o k response
func (o *DiagnosticsGetSeatServerStatusOK) Code() int {
	return 200
}

func (o *DiagnosticsGetSeatServerStatusOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Diagnostics/SeatServerStatus][%d] diagnosticsGetSeatServerStatusOK %s", 200, payload)
}

func (o *DiagnosticsGetSeatServerStatusOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Diagnostics/SeatServerStatus][%d] diagnosticsGetSeatServerStatusOK %s", 200, payload)
}

func (o *DiagnosticsGetSeatServerStatusOK) GetPayload() *models.SeatServerStatus {
	return o.Payload
}

func (o *DiagnosticsGetSeatServerStatusOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SeatServerStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDiagnosticsGetSeatServerStatusDefault creates a DiagnosticsGetSeatServerStatusDefault with default headers values
func NewDiagnosticsGetSeatServerStatusDefault(code int) *DiagnosticsGetSeatServerStatusDefault {
	return &DiagnosticsGetSeatServerStatusDefault{
		_statusCode: code,
	}
}

/*
DiagnosticsGetSeatServerStatusDefault describes a response with status code -1, with default header values.

Error
*/
type DiagnosticsGetSeatServerStatusDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this diagnostics get seat server status default response has a 2xx status code
func (o *DiagnosticsGetSeatServerStatusDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this diagnostics get seat server status default response has a 3xx status code
func (o *DiagnosticsGetSeatServerStatusDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this diagnostics get seat server status default response has a 4xx status code
func (o *DiagnosticsGetSeatServerStatusDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this diagnostics get seat server status default response has a 5xx status code
func (o *DiagnosticsGetSeatServerStatusDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this diagnostics get seat server status default response a status code equal to that given
func (o *DiagnosticsGetSeatServerStatusDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the diagnostics get seat server status default response
func (o *DiagnosticsGetSeatServerStatusDefault) Code() int {
	return o._statusCode
}

func (o *DiagnosticsGetSeatServerStatusDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Diagnostics/SeatServerStatus][%d] Diagnostics_GetSeatServerStatus default %s", o._statusCode, payload)
}

func (o *DiagnosticsGetSeatServerStatusDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Diagnostics/SeatServerStatus][%d] Diagnostics_GetSeatServerStatus default %s", o._statusCode, payload)
}

func (o *DiagnosticsGetSeatServerStatusDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *DiagnosticsGetSeatServerStatusDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
