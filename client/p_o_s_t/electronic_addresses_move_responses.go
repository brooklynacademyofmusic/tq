// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// ElectronicAddressesMoveReader is a Reader for the ElectronicAddressesMove structure.
type ElectronicAddressesMoveReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ElectronicAddressesMoveReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewElectronicAddressesMoveOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /CRM/ElectronicAddresses/{electronicAddressId}/MoveTo/{constituentId}] ElectronicAddresses_Move", response, response.Code())
	}
}

// NewElectronicAddressesMoveOK creates a ElectronicAddressesMoveOK with default headers values
func NewElectronicAddressesMoveOK() *ElectronicAddressesMoveOK {
	return &ElectronicAddressesMoveOK{}
}

/*
ElectronicAddressesMoveOK describes a response with status code 200, with default header values.

OK
*/
type ElectronicAddressesMoveOK struct {
	Payload *models.ElectronicAddress
}

// IsSuccess returns true when this electronic addresses move o k response has a 2xx status code
func (o *ElectronicAddressesMoveOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this electronic addresses move o k response has a 3xx status code
func (o *ElectronicAddressesMoveOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this electronic addresses move o k response has a 4xx status code
func (o *ElectronicAddressesMoveOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this electronic addresses move o k response has a 5xx status code
func (o *ElectronicAddressesMoveOK) IsServerError() bool {
	return false
}

// IsCode returns true when this electronic addresses move o k response a status code equal to that given
func (o *ElectronicAddressesMoveOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the electronic addresses move o k response
func (o *ElectronicAddressesMoveOK) Code() int {
	return 200
}

func (o *ElectronicAddressesMoveOK) Error() string {
	return fmt.Sprintf("[POST /CRM/ElectronicAddresses/{electronicAddressId}/MoveTo/{constituentId}][%d] electronicAddressesMoveOK  %+v", 200, o.Payload)
}

func (o *ElectronicAddressesMoveOK) String() string {
	return fmt.Sprintf("[POST /CRM/ElectronicAddresses/{electronicAddressId}/MoveTo/{constituentId}][%d] electronicAddressesMoveOK  %+v", 200, o.Payload)
}

func (o *ElectronicAddressesMoveOK) GetPayload() *models.ElectronicAddress {
	return o.Payload
}

func (o *ElectronicAddressesMoveOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ElectronicAddress)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}