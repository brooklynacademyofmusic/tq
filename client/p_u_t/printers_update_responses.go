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

// PrintersUpdateReader is a Reader for the PrintersUpdate structure.
type PrintersUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PrintersUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPrintersUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPrintersUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPrintersUpdateOK creates a PrintersUpdateOK with default headers values
func NewPrintersUpdateOK() *PrintersUpdateOK {
	return &PrintersUpdateOK{}
}

/*
PrintersUpdateOK describes a response with status code 200, with default header values.

OK
*/
type PrintersUpdateOK struct {
	Payload *models.Printer
}

// IsSuccess returns true when this printers update o k response has a 2xx status code
func (o *PrintersUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this printers update o k response has a 3xx status code
func (o *PrintersUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this printers update o k response has a 4xx status code
func (o *PrintersUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this printers update o k response has a 5xx status code
func (o *PrintersUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this printers update o k response a status code equal to that given
func (o *PrintersUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the printers update o k response
func (o *PrintersUpdateOK) Code() int {
	return 200
}

func (o *PrintersUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Printers/{id}][%d] printersUpdateOK %s", 200, payload)
}

func (o *PrintersUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Printers/{id}][%d] printersUpdateOK %s", 200, payload)
}

func (o *PrintersUpdateOK) GetPayload() *models.Printer {
	return o.Payload
}

func (o *PrintersUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Printer)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPrintersUpdateDefault creates a PrintersUpdateDefault with default headers values
func NewPrintersUpdateDefault(code int) *PrintersUpdateDefault {
	return &PrintersUpdateDefault{
		_statusCode: code,
	}
}

/*
PrintersUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type PrintersUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this printers update default response has a 2xx status code
func (o *PrintersUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this printers update default response has a 3xx status code
func (o *PrintersUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this printers update default response has a 4xx status code
func (o *PrintersUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this printers update default response has a 5xx status code
func (o *PrintersUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this printers update default response a status code equal to that given
func (o *PrintersUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the printers update default response
func (o *PrintersUpdateDefault) Code() int {
	return o._statusCode
}

func (o *PrintersUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Printers/{id}][%d] Printers_Update default %s", o._statusCode, payload)
}

func (o *PrintersUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Printers/{id}][%d] Printers_Update default %s", o._statusCode, payload)
}

func (o *PrintersUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PrintersUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
