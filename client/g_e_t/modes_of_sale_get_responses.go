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

// ModesOfSaleGetReader is a Reader for the ModesOfSaleGet structure.
type ModesOfSaleGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ModesOfSaleGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewModesOfSaleGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewModesOfSaleGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewModesOfSaleGetOK creates a ModesOfSaleGetOK with default headers values
func NewModesOfSaleGetOK() *ModesOfSaleGetOK {
	return &ModesOfSaleGetOK{}
}

/*
ModesOfSaleGetOK describes a response with status code 200, with default header values.

OK
*/
type ModesOfSaleGetOK struct {
	Payload *models.ModeOfSale
}

// IsSuccess returns true when this modes of sale get o k response has a 2xx status code
func (o *ModesOfSaleGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this modes of sale get o k response has a 3xx status code
func (o *ModesOfSaleGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this modes of sale get o k response has a 4xx status code
func (o *ModesOfSaleGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this modes of sale get o k response has a 5xx status code
func (o *ModesOfSaleGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this modes of sale get o k response a status code equal to that given
func (o *ModesOfSaleGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the modes of sale get o k response
func (o *ModesOfSaleGetOK) Code() int {
	return 200
}

func (o *ModesOfSaleGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ModesOfSale/{modeOfSaleId}][%d] modesOfSaleGetOK %s", 200, payload)
}

func (o *ModesOfSaleGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ModesOfSale/{modeOfSaleId}][%d] modesOfSaleGetOK %s", 200, payload)
}

func (o *ModesOfSaleGetOK) GetPayload() *models.ModeOfSale {
	return o.Payload
}

func (o *ModesOfSaleGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ModeOfSale)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewModesOfSaleGetDefault creates a ModesOfSaleGetDefault with default headers values
func NewModesOfSaleGetDefault(code int) *ModesOfSaleGetDefault {
	return &ModesOfSaleGetDefault{
		_statusCode: code,
	}
}

/*
ModesOfSaleGetDefault describes a response with status code -1, with default header values.

Error
*/
type ModesOfSaleGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this modes of sale get default response has a 2xx status code
func (o *ModesOfSaleGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this modes of sale get default response has a 3xx status code
func (o *ModesOfSaleGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this modes of sale get default response has a 4xx status code
func (o *ModesOfSaleGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this modes of sale get default response has a 5xx status code
func (o *ModesOfSaleGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this modes of sale get default response a status code equal to that given
func (o *ModesOfSaleGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the modes of sale get default response
func (o *ModesOfSaleGetDefault) Code() int {
	return o._statusCode
}

func (o *ModesOfSaleGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ModesOfSale/{modeOfSaleId}][%d] ModesOfSale_Get default %s", o._statusCode, payload)
}

func (o *ModesOfSaleGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ModesOfSale/{modeOfSaleId}][%d] ModesOfSale_Get default %s", o._statusCode, payload)
}

func (o *ModesOfSaleGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ModesOfSaleGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
