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

// FormatsGetReader is a Reader for the FormatsGet structure.
type FormatsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *FormatsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewFormatsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewFormatsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewFormatsGetOK creates a FormatsGetOK with default headers values
func NewFormatsGetOK() *FormatsGetOK {
	return &FormatsGetOK{}
}

/*
FormatsGetOK describes a response with status code 200, with default header values.

OK
*/
type FormatsGetOK struct {
	Payload *models.Format
}

// IsSuccess returns true when this formats get o k response has a 2xx status code
func (o *FormatsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this formats get o k response has a 3xx status code
func (o *FormatsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this formats get o k response has a 4xx status code
func (o *FormatsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this formats get o k response has a 5xx status code
func (o *FormatsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this formats get o k response a status code equal to that given
func (o *FormatsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the formats get o k response
func (o *FormatsGetOK) Code() int {
	return 200
}

func (o *FormatsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Formats/{id}][%d] formatsGetOK %s", 200, payload)
}

func (o *FormatsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Formats/{id}][%d] formatsGetOK %s", 200, payload)
}

func (o *FormatsGetOK) GetPayload() *models.Format {
	return o.Payload
}

func (o *FormatsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Format)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFormatsGetDefault creates a FormatsGetDefault with default headers values
func NewFormatsGetDefault(code int) *FormatsGetDefault {
	return &FormatsGetDefault{
		_statusCode: code,
	}
}

/*
FormatsGetDefault describes a response with status code -1, with default header values.

Error
*/
type FormatsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this formats get default response has a 2xx status code
func (o *FormatsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this formats get default response has a 3xx status code
func (o *FormatsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this formats get default response has a 4xx status code
func (o *FormatsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this formats get default response has a 5xx status code
func (o *FormatsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this formats get default response a status code equal to that given
func (o *FormatsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the formats get default response
func (o *FormatsGetDefault) Code() int {
	return o._statusCode
}

func (o *FormatsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Formats/{id}][%d] Formats_Get default %s", o._statusCode, payload)
}

func (o *FormatsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Formats/{id}][%d] Formats_Get default %s", o._statusCode, payload)
}

func (o *FormatsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *FormatsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}