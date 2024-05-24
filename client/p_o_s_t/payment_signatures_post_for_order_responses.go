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

// PaymentSignaturesPostForOrderReader is a Reader for the PaymentSignaturesPostForOrder structure.
type PaymentSignaturesPostForOrderReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentSignaturesPostForOrderReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentSignaturesPostForOrderOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentSignaturesPostForOrderDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentSignaturesPostForOrderOK creates a PaymentSignaturesPostForOrderOK with default headers values
func NewPaymentSignaturesPostForOrderOK() *PaymentSignaturesPostForOrderOK {
	return &PaymentSignaturesPostForOrderOK{}
}

/*
PaymentSignaturesPostForOrderOK describes a response with status code 200, with default header values.

OK
*/
type PaymentSignaturesPostForOrderOK struct {
	Payload *models.PaymentSignature
}

// IsSuccess returns true when this payment signatures post for order o k response has a 2xx status code
func (o *PaymentSignaturesPostForOrderOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment signatures post for order o k response has a 3xx status code
func (o *PaymentSignaturesPostForOrderOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment signatures post for order o k response has a 4xx status code
func (o *PaymentSignaturesPostForOrderOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment signatures post for order o k response has a 5xx status code
func (o *PaymentSignaturesPostForOrderOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment signatures post for order o k response a status code equal to that given
func (o *PaymentSignaturesPostForOrderOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment signatures post for order o k response
func (o *PaymentSignaturesPostForOrderOK) Code() int {
	return 200
}

func (o *PaymentSignaturesPostForOrderOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/Payment/Signatures/Order/{orderId}][%d] paymentSignaturesPostForOrderOK %s", 200, payload)
}

func (o *PaymentSignaturesPostForOrderOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/Payment/Signatures/Order/{orderId}][%d] paymentSignaturesPostForOrderOK %s", 200, payload)
}

func (o *PaymentSignaturesPostForOrderOK) GetPayload() *models.PaymentSignature {
	return o.Payload
}

func (o *PaymentSignaturesPostForOrderOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PaymentSignature)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentSignaturesPostForOrderDefault creates a PaymentSignaturesPostForOrderDefault with default headers values
func NewPaymentSignaturesPostForOrderDefault(code int) *PaymentSignaturesPostForOrderDefault {
	return &PaymentSignaturesPostForOrderDefault{
		_statusCode: code,
	}
}

/*
PaymentSignaturesPostForOrderDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentSignaturesPostForOrderDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment signatures post for order default response has a 2xx status code
func (o *PaymentSignaturesPostForOrderDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment signatures post for order default response has a 3xx status code
func (o *PaymentSignaturesPostForOrderDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment signatures post for order default response has a 4xx status code
func (o *PaymentSignaturesPostForOrderDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment signatures post for order default response has a 5xx status code
func (o *PaymentSignaturesPostForOrderDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment signatures post for order default response a status code equal to that given
func (o *PaymentSignaturesPostForOrderDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment signatures post for order default response
func (o *PaymentSignaturesPostForOrderDefault) Code() int {
	return o._statusCode
}

func (o *PaymentSignaturesPostForOrderDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/Payment/Signatures/Order/{orderId}][%d] PaymentSignatures_PostForOrder default %s", o._statusCode, payload)
}

func (o *PaymentSignaturesPostForOrderDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/Payment/Signatures/Order/{orderId}][%d] PaymentSignatures_PostForOrder default %s", o._statusCode, payload)
}

func (o *PaymentSignaturesPostForOrderDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentSignaturesPostForOrderDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
