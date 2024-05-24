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

// PhonesGetReader is a Reader for the PhonesGet structure.
type PhonesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PhonesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPhonesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPhonesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPhonesGetOK creates a PhonesGetOK with default headers values
func NewPhonesGetOK() *PhonesGetOK {
	return &PhonesGetOK{}
}

/*
PhonesGetOK describes a response with status code 200, with default header values.

OK
*/
type PhonesGetOK struct {
	Payload *models.Phone
}

// IsSuccess returns true when this phones get o k response has a 2xx status code
func (o *PhonesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this phones get o k response has a 3xx status code
func (o *PhonesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this phones get o k response has a 4xx status code
func (o *PhonesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this phones get o k response has a 5xx status code
func (o *PhonesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this phones get o k response a status code equal to that given
func (o *PhonesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the phones get o k response
func (o *PhonesGetOK) Code() int {
	return 200
}

func (o *PhonesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Phones/{phoneId}][%d] phonesGetOK %s", 200, payload)
}

func (o *PhonesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Phones/{phoneId}][%d] phonesGetOK %s", 200, payload)
}

func (o *PhonesGetOK) GetPayload() *models.Phone {
	return o.Payload
}

func (o *PhonesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Phone)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPhonesGetDefault creates a PhonesGetDefault with default headers values
func NewPhonesGetDefault(code int) *PhonesGetDefault {
	return &PhonesGetDefault{
		_statusCode: code,
	}
}

/*
PhonesGetDefault describes a response with status code -1, with default header values.

Error
*/
type PhonesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this phones get default response has a 2xx status code
func (o *PhonesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this phones get default response has a 3xx status code
func (o *PhonesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this phones get default response has a 4xx status code
func (o *PhonesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this phones get default response has a 5xx status code
func (o *PhonesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this phones get default response a status code equal to that given
func (o *PhonesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the phones get default response
func (o *PhonesGetDefault) Code() int {
	return o._statusCode
}

func (o *PhonesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Phones/{phoneId}][%d] Phones_Get default %s", o._statusCode, payload)
}

func (o *PhonesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Phones/{phoneId}][%d] Phones_Get default %s", o._statusCode, payload)
}

func (o *PhonesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PhonesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
