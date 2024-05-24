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

// TemplatePriceTypesUpdateReader is a Reader for the TemplatePriceTypesUpdate structure.
type TemplatePriceTypesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TemplatePriceTypesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTemplatePriceTypesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewTemplatePriceTypesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewTemplatePriceTypesUpdateOK creates a TemplatePriceTypesUpdateOK with default headers values
func NewTemplatePriceTypesUpdateOK() *TemplatePriceTypesUpdateOK {
	return &TemplatePriceTypesUpdateOK{}
}

/*
TemplatePriceTypesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type TemplatePriceTypesUpdateOK struct {
	Payload *models.TemplatePriceType
}

// IsSuccess returns true when this template price types update o k response has a 2xx status code
func (o *TemplatePriceTypesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this template price types update o k response has a 3xx status code
func (o *TemplatePriceTypesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this template price types update o k response has a 4xx status code
func (o *TemplatePriceTypesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this template price types update o k response has a 5xx status code
func (o *TemplatePriceTypesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this template price types update o k response a status code equal to that given
func (o *TemplatePriceTypesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the template price types update o k response
func (o *TemplatePriceTypesUpdateOK) Code() int {
	return 200
}

func (o *TemplatePriceTypesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/TemplatePriceTypes/{templatePriceTypeId}][%d] templatePriceTypesUpdateOK %s", 200, payload)
}

func (o *TemplatePriceTypesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/TemplatePriceTypes/{templatePriceTypeId}][%d] templatePriceTypesUpdateOK %s", 200, payload)
}

func (o *TemplatePriceTypesUpdateOK) GetPayload() *models.TemplatePriceType {
	return o.Payload
}

func (o *TemplatePriceTypesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TemplatePriceType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTemplatePriceTypesUpdateDefault creates a TemplatePriceTypesUpdateDefault with default headers values
func NewTemplatePriceTypesUpdateDefault(code int) *TemplatePriceTypesUpdateDefault {
	return &TemplatePriceTypesUpdateDefault{
		_statusCode: code,
	}
}

/*
TemplatePriceTypesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type TemplatePriceTypesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this template price types update default response has a 2xx status code
func (o *TemplatePriceTypesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this template price types update default response has a 3xx status code
func (o *TemplatePriceTypesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this template price types update default response has a 4xx status code
func (o *TemplatePriceTypesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this template price types update default response has a 5xx status code
func (o *TemplatePriceTypesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this template price types update default response a status code equal to that given
func (o *TemplatePriceTypesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the template price types update default response
func (o *TemplatePriceTypesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *TemplatePriceTypesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/TemplatePriceTypes/{templatePriceTypeId}][%d] TemplatePriceTypes_Update default %s", o._statusCode, payload)
}

func (o *TemplatePriceTypesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/TemplatePriceTypes/{templatePriceTypeId}][%d] TemplatePriceTypes_Update default %s", o._statusCode, payload)
}

func (o *TemplatePriceTypesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *TemplatePriceTypesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
