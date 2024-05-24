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

// AddressesGetReader is a Reader for the AddressesGet structure.
type AddressesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AddressesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAddressesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAddressesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAddressesGetOK creates a AddressesGetOK with default headers values
func NewAddressesGetOK() *AddressesGetOK {
	return &AddressesGetOK{}
}

/*
AddressesGetOK describes a response with status code 200, with default header values.

OK
*/
type AddressesGetOK struct {
	Payload *models.Address
}

// IsSuccess returns true when this addresses get o k response has a 2xx status code
func (o *AddressesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this addresses get o k response has a 3xx status code
func (o *AddressesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this addresses get o k response has a 4xx status code
func (o *AddressesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this addresses get o k response has a 5xx status code
func (o *AddressesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this addresses get o k response a status code equal to that given
func (o *AddressesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the addresses get o k response
func (o *AddressesGetOK) Code() int {
	return 200
}

func (o *AddressesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Addresses/{addressId}][%d] addressesGetOK %s", 200, payload)
}

func (o *AddressesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Addresses/{addressId}][%d] addressesGetOK %s", 200, payload)
}

func (o *AddressesGetOK) GetPayload() *models.Address {
	return o.Payload
}

func (o *AddressesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Address)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddressesGetDefault creates a AddressesGetDefault with default headers values
func NewAddressesGetDefault(code int) *AddressesGetDefault {
	return &AddressesGetDefault{
		_statusCode: code,
	}
}

/*
AddressesGetDefault describes a response with status code -1, with default header values.

Error
*/
type AddressesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this addresses get default response has a 2xx status code
func (o *AddressesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this addresses get default response has a 3xx status code
func (o *AddressesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this addresses get default response has a 4xx status code
func (o *AddressesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this addresses get default response has a 5xx status code
func (o *AddressesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this addresses get default response a status code equal to that given
func (o *AddressesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the addresses get default response
func (o *AddressesGetDefault) Code() int {
	return o._statusCode
}

func (o *AddressesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Addresses/{addressId}][%d] Addresses_Get default %s", o._statusCode, payload)
}

func (o *AddressesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Addresses/{addressId}][%d] Addresses_Get default %s", o._statusCode, payload)
}

func (o *AddressesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AddressesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
