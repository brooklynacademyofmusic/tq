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

// PaymentSignaturesGetReader is a Reader for the PaymentSignaturesGet structure.
type PaymentSignaturesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentSignaturesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentSignaturesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentSignaturesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentSignaturesGetOK creates a PaymentSignaturesGetOK with default headers values
func NewPaymentSignaturesGetOK() *PaymentSignaturesGetOK {
	return &PaymentSignaturesGetOK{}
}

/*
PaymentSignaturesGetOK describes a response with status code 200, with default header values.

OK
*/
type PaymentSignaturesGetOK struct {
	Payload *models.PaymentSignature
}

// IsSuccess returns true when this payment signatures get o k response has a 2xx status code
func (o *PaymentSignaturesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment signatures get o k response has a 3xx status code
func (o *PaymentSignaturesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment signatures get o k response has a 4xx status code
func (o *PaymentSignaturesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment signatures get o k response has a 5xx status code
func (o *PaymentSignaturesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment signatures get o k response a status code equal to that given
func (o *PaymentSignaturesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment signatures get o k response
func (o *PaymentSignaturesGetOK) Code() int {
	return 200
}

func (o *PaymentSignaturesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Payment/Signatures/{paymentSignatureId}][%d] paymentSignaturesGetOK %s", 200, payload)
}

func (o *PaymentSignaturesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Payment/Signatures/{paymentSignatureId}][%d] paymentSignaturesGetOK %s", 200, payload)
}

func (o *PaymentSignaturesGetOK) GetPayload() *models.PaymentSignature {
	return o.Payload
}

func (o *PaymentSignaturesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PaymentSignature)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentSignaturesGetDefault creates a PaymentSignaturesGetDefault with default headers values
func NewPaymentSignaturesGetDefault(code int) *PaymentSignaturesGetDefault {
	return &PaymentSignaturesGetDefault{
		_statusCode: code,
	}
}

/*
PaymentSignaturesGetDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentSignaturesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment signatures get default response has a 2xx status code
func (o *PaymentSignaturesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment signatures get default response has a 3xx status code
func (o *PaymentSignaturesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment signatures get default response has a 4xx status code
func (o *PaymentSignaturesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment signatures get default response has a 5xx status code
func (o *PaymentSignaturesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment signatures get default response a status code equal to that given
func (o *PaymentSignaturesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment signatures get default response
func (o *PaymentSignaturesGetDefault) Code() int {
	return o._statusCode
}

func (o *PaymentSignaturesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Payment/Signatures/{paymentSignatureId}][%d] PaymentSignatures_Get default %s", o._statusCode, payload)
}

func (o *PaymentSignaturesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Payment/Signatures/{paymentSignatureId}][%d] PaymentSignatures_Get default %s", o._statusCode, payload)
}

func (o *PaymentSignaturesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentSignaturesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}