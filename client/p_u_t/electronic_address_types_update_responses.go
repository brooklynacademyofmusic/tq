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

// ElectronicAddressTypesUpdateReader is a Reader for the ElectronicAddressTypesUpdate structure.
type ElectronicAddressTypesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ElectronicAddressTypesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewElectronicAddressTypesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewElectronicAddressTypesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewElectronicAddressTypesUpdateOK creates a ElectronicAddressTypesUpdateOK with default headers values
func NewElectronicAddressTypesUpdateOK() *ElectronicAddressTypesUpdateOK {
	return &ElectronicAddressTypesUpdateOK{}
}

/*
ElectronicAddressTypesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type ElectronicAddressTypesUpdateOK struct {
	Payload *models.ElectronicAddressType
}

// IsSuccess returns true when this electronic address types update o k response has a 2xx status code
func (o *ElectronicAddressTypesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this electronic address types update o k response has a 3xx status code
func (o *ElectronicAddressTypesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this electronic address types update o k response has a 4xx status code
func (o *ElectronicAddressTypesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this electronic address types update o k response has a 5xx status code
func (o *ElectronicAddressTypesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this electronic address types update o k response a status code equal to that given
func (o *ElectronicAddressTypesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the electronic address types update o k response
func (o *ElectronicAddressTypesUpdateOK) Code() int {
	return 200
}

func (o *ElectronicAddressTypesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ElectronicAddressTypes/{id}][%d] electronicAddressTypesUpdateOK %s", 200, payload)
}

func (o *ElectronicAddressTypesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ElectronicAddressTypes/{id}][%d] electronicAddressTypesUpdateOK %s", 200, payload)
}

func (o *ElectronicAddressTypesUpdateOK) GetPayload() *models.ElectronicAddressType {
	return o.Payload
}

func (o *ElectronicAddressTypesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ElectronicAddressType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewElectronicAddressTypesUpdateDefault creates a ElectronicAddressTypesUpdateDefault with default headers values
func NewElectronicAddressTypesUpdateDefault(code int) *ElectronicAddressTypesUpdateDefault {
	return &ElectronicAddressTypesUpdateDefault{
		_statusCode: code,
	}
}

/*
ElectronicAddressTypesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type ElectronicAddressTypesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this electronic address types update default response has a 2xx status code
func (o *ElectronicAddressTypesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this electronic address types update default response has a 3xx status code
func (o *ElectronicAddressTypesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this electronic address types update default response has a 4xx status code
func (o *ElectronicAddressTypesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this electronic address types update default response has a 5xx status code
func (o *ElectronicAddressTypesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this electronic address types update default response a status code equal to that given
func (o *ElectronicAddressTypesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the electronic address types update default response
func (o *ElectronicAddressTypesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *ElectronicAddressTypesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ElectronicAddressTypes/{id}][%d] ElectronicAddressTypes_Update default %s", o._statusCode, payload)
}

func (o *ElectronicAddressTypesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ElectronicAddressTypes/{id}][%d] ElectronicAddressTypes_Update default %s", o._statusCode, payload)
}

func (o *ElectronicAddressTypesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ElectronicAddressTypesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}