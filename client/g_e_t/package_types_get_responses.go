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

// PackageTypesGetReader is a Reader for the PackageTypesGet structure.
type PackageTypesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PackageTypesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPackageTypesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPackageTypesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPackageTypesGetOK creates a PackageTypesGetOK with default headers values
func NewPackageTypesGetOK() *PackageTypesGetOK {
	return &PackageTypesGetOK{}
}

/*
PackageTypesGetOK describes a response with status code 200, with default header values.

OK
*/
type PackageTypesGetOK struct {
	Payload *models.PackageType
}

// IsSuccess returns true when this package types get o k response has a 2xx status code
func (o *PackageTypesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this package types get o k response has a 3xx status code
func (o *PackageTypesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this package types get o k response has a 4xx status code
func (o *PackageTypesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this package types get o k response has a 5xx status code
func (o *PackageTypesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this package types get o k response a status code equal to that given
func (o *PackageTypesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the package types get o k response
func (o *PackageTypesGetOK) Code() int {
	return 200
}

func (o *PackageTypesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PackageTypes/{id}][%d] packageTypesGetOK %s", 200, payload)
}

func (o *PackageTypesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PackageTypes/{id}][%d] packageTypesGetOK %s", 200, payload)
}

func (o *PackageTypesGetOK) GetPayload() *models.PackageType {
	return o.Payload
}

func (o *PackageTypesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PackageType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPackageTypesGetDefault creates a PackageTypesGetDefault with default headers values
func NewPackageTypesGetDefault(code int) *PackageTypesGetDefault {
	return &PackageTypesGetDefault{
		_statusCode: code,
	}
}

/*
PackageTypesGetDefault describes a response with status code -1, with default header values.

Error
*/
type PackageTypesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this package types get default response has a 2xx status code
func (o *PackageTypesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this package types get default response has a 3xx status code
func (o *PackageTypesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this package types get default response has a 4xx status code
func (o *PackageTypesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this package types get default response has a 5xx status code
func (o *PackageTypesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this package types get default response a status code equal to that given
func (o *PackageTypesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the package types get default response
func (o *PackageTypesGetDefault) Code() int {
	return o._statusCode
}

func (o *PackageTypesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PackageTypes/{id}][%d] PackageTypes_Get default %s", o._statusCode, payload)
}

func (o *PackageTypesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PackageTypes/{id}][%d] PackageTypes_Get default %s", o._statusCode, payload)
}

func (o *PackageTypesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PackageTypesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
