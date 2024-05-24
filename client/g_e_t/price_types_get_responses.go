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

// PriceTypesGetReader is a Reader for the PriceTypesGet structure.
type PriceTypesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PriceTypesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPriceTypesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPriceTypesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPriceTypesGetOK creates a PriceTypesGetOK with default headers values
func NewPriceTypesGetOK() *PriceTypesGetOK {
	return &PriceTypesGetOK{}
}

/*
PriceTypesGetOK describes a response with status code 200, with default header values.

OK
*/
type PriceTypesGetOK struct {
	Payload *models.PriceType
}

// IsSuccess returns true when this price types get o k response has a 2xx status code
func (o *PriceTypesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this price types get o k response has a 3xx status code
func (o *PriceTypesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this price types get o k response has a 4xx status code
func (o *PriceTypesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this price types get o k response has a 5xx status code
func (o *PriceTypesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this price types get o k response a status code equal to that given
func (o *PriceTypesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the price types get o k response
func (o *PriceTypesGetOK) Code() int {
	return 200
}

func (o *PriceTypesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypes/{priceTypeId}][%d] priceTypesGetOK %s", 200, payload)
}

func (o *PriceTypesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypes/{priceTypeId}][%d] priceTypesGetOK %s", 200, payload)
}

func (o *PriceTypesGetOK) GetPayload() *models.PriceType {
	return o.Payload
}

func (o *PriceTypesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PriceType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPriceTypesGetDefault creates a PriceTypesGetDefault with default headers values
func NewPriceTypesGetDefault(code int) *PriceTypesGetDefault {
	return &PriceTypesGetDefault{
		_statusCode: code,
	}
}

/*
PriceTypesGetDefault describes a response with status code -1, with default header values.

Error
*/
type PriceTypesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this price types get default response has a 2xx status code
func (o *PriceTypesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this price types get default response has a 3xx status code
func (o *PriceTypesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this price types get default response has a 4xx status code
func (o *PriceTypesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this price types get default response has a 5xx status code
func (o *PriceTypesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this price types get default response a status code equal to that given
func (o *PriceTypesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the price types get default response
func (o *PriceTypesGetDefault) Code() int {
	return o._statusCode
}

func (o *PriceTypesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypes/{priceTypeId}][%d] PriceTypes_Get default %s", o._statusCode, payload)
}

func (o *PriceTypesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypes/{priceTypeId}][%d] PriceTypes_Get default %s", o._statusCode, payload)
}

func (o *PriceTypesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PriceTypesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
