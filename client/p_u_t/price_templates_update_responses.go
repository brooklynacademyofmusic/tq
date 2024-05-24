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

// PriceTemplatesUpdateReader is a Reader for the PriceTemplatesUpdate structure.
type PriceTemplatesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PriceTemplatesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPriceTemplatesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPriceTemplatesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPriceTemplatesUpdateOK creates a PriceTemplatesUpdateOK with default headers values
func NewPriceTemplatesUpdateOK() *PriceTemplatesUpdateOK {
	return &PriceTemplatesUpdateOK{}
}

/*
PriceTemplatesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type PriceTemplatesUpdateOK struct {
	Payload *models.PriceTemplate
}

// IsSuccess returns true when this price templates update o k response has a 2xx status code
func (o *PriceTemplatesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this price templates update o k response has a 3xx status code
func (o *PriceTemplatesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this price templates update o k response has a 4xx status code
func (o *PriceTemplatesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this price templates update o k response has a 5xx status code
func (o *PriceTemplatesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this price templates update o k response a status code equal to that given
func (o *PriceTemplatesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the price templates update o k response
func (o *PriceTemplatesUpdateOK) Code() int {
	return 200
}

func (o *PriceTemplatesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/PriceTemplates/{priceTemplateId}][%d] priceTemplatesUpdateOK %s", 200, payload)
}

func (o *PriceTemplatesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/PriceTemplates/{priceTemplateId}][%d] priceTemplatesUpdateOK %s", 200, payload)
}

func (o *PriceTemplatesUpdateOK) GetPayload() *models.PriceTemplate {
	return o.Payload
}

func (o *PriceTemplatesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PriceTemplate)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPriceTemplatesUpdateDefault creates a PriceTemplatesUpdateDefault with default headers values
func NewPriceTemplatesUpdateDefault(code int) *PriceTemplatesUpdateDefault {
	return &PriceTemplatesUpdateDefault{
		_statusCode: code,
	}
}

/*
PriceTemplatesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type PriceTemplatesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this price templates update default response has a 2xx status code
func (o *PriceTemplatesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this price templates update default response has a 3xx status code
func (o *PriceTemplatesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this price templates update default response has a 4xx status code
func (o *PriceTemplatesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this price templates update default response has a 5xx status code
func (o *PriceTemplatesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this price templates update default response a status code equal to that given
func (o *PriceTemplatesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the price templates update default response
func (o *PriceTemplatesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *PriceTemplatesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/PriceTemplates/{priceTemplateId}][%d] PriceTemplates_Update default %s", o._statusCode, payload)
}

func (o *PriceTemplatesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/PriceTemplates/{priceTemplateId}][%d] PriceTemplates_Update default %s", o._statusCode, payload)
}

func (o *PriceTemplatesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PriceTemplatesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
