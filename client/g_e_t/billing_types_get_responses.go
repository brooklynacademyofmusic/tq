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

// BillingTypesGetReader is a Reader for the BillingTypesGet structure.
type BillingTypesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BillingTypesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewBillingTypesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewBillingTypesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewBillingTypesGetOK creates a BillingTypesGetOK with default headers values
func NewBillingTypesGetOK() *BillingTypesGetOK {
	return &BillingTypesGetOK{}
}

/*
BillingTypesGetOK describes a response with status code 200, with default header values.

OK
*/
type BillingTypesGetOK struct {
	Payload *models.BillingType
}

// IsSuccess returns true when this billing types get o k response has a 2xx status code
func (o *BillingTypesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this billing types get o k response has a 3xx status code
func (o *BillingTypesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this billing types get o k response has a 4xx status code
func (o *BillingTypesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this billing types get o k response has a 5xx status code
func (o *BillingTypesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this billing types get o k response a status code equal to that given
func (o *BillingTypesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the billing types get o k response
func (o *BillingTypesGetOK) Code() int {
	return 200
}

func (o *BillingTypesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/BillingTypes/{id}][%d] billingTypesGetOK %s", 200, payload)
}

func (o *BillingTypesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/BillingTypes/{id}][%d] billingTypesGetOK %s", 200, payload)
}

func (o *BillingTypesGetOK) GetPayload() *models.BillingType {
	return o.Payload
}

func (o *BillingTypesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BillingType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBillingTypesGetDefault creates a BillingTypesGetDefault with default headers values
func NewBillingTypesGetDefault(code int) *BillingTypesGetDefault {
	return &BillingTypesGetDefault{
		_statusCode: code,
	}
}

/*
BillingTypesGetDefault describes a response with status code -1, with default header values.

Error
*/
type BillingTypesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this billing types get default response has a 2xx status code
func (o *BillingTypesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this billing types get default response has a 3xx status code
func (o *BillingTypesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this billing types get default response has a 4xx status code
func (o *BillingTypesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this billing types get default response has a 5xx status code
func (o *BillingTypesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this billing types get default response a status code equal to that given
func (o *BillingTypesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the billing types get default response
func (o *BillingTypesGetDefault) Code() int {
	return o._statusCode
}

func (o *BillingTypesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/BillingTypes/{id}][%d] BillingTypes_Get default %s", o._statusCode, payload)
}

func (o *BillingTypesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/BillingTypes/{id}][%d] BillingTypes_Get default %s", o._statusCode, payload)
}

func (o *BillingTypesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *BillingTypesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
