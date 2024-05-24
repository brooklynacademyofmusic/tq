// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

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

// PaymentTypesCreateReader is a Reader for the PaymentTypesCreate structure.
type PaymentTypesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentTypesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentTypesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentTypesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentTypesCreateOK creates a PaymentTypesCreateOK with default headers values
func NewPaymentTypesCreateOK() *PaymentTypesCreateOK {
	return &PaymentTypesCreateOK{}
}

/*
PaymentTypesCreateOK describes a response with status code 200, with default header values.

OK
*/
type PaymentTypesCreateOK struct {
	Payload *models.PaymentType
}

// IsSuccess returns true when this payment types create o k response has a 2xx status code
func (o *PaymentTypesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment types create o k response has a 3xx status code
func (o *PaymentTypesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment types create o k response has a 4xx status code
func (o *PaymentTypesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment types create o k response has a 5xx status code
func (o *PaymentTypesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment types create o k response a status code equal to that given
func (o *PaymentTypesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment types create o k response
func (o *PaymentTypesCreateOK) Code() int {
	return 200
}

func (o *PaymentTypesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PaymentTypes][%d] paymentTypesCreateOK %s", 200, payload)
}

func (o *PaymentTypesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PaymentTypes][%d] paymentTypesCreateOK %s", 200, payload)
}

func (o *PaymentTypesCreateOK) GetPayload() *models.PaymentType {
	return o.Payload
}

func (o *PaymentTypesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PaymentType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentTypesCreateDefault creates a PaymentTypesCreateDefault with default headers values
func NewPaymentTypesCreateDefault(code int) *PaymentTypesCreateDefault {
	return &PaymentTypesCreateDefault{
		_statusCode: code,
	}
}

/*
PaymentTypesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentTypesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment types create default response has a 2xx status code
func (o *PaymentTypesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment types create default response has a 3xx status code
func (o *PaymentTypesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment types create default response has a 4xx status code
func (o *PaymentTypesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment types create default response has a 5xx status code
func (o *PaymentTypesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment types create default response a status code equal to that given
func (o *PaymentTypesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment types create default response
func (o *PaymentTypesCreateDefault) Code() int {
	return o._statusCode
}

func (o *PaymentTypesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PaymentTypes][%d] PaymentTypes_Create default %s", o._statusCode, payload)
}

func (o *PaymentTypesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PaymentTypes][%d] PaymentTypes_Create default %s", o._statusCode, payload)
}

func (o *PaymentTypesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentTypesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
