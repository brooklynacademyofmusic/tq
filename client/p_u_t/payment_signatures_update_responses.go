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

// PaymentSignaturesUpdateReader is a Reader for the PaymentSignaturesUpdate structure.
type PaymentSignaturesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentSignaturesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentSignaturesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentSignaturesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentSignaturesUpdateOK creates a PaymentSignaturesUpdateOK with default headers values
func NewPaymentSignaturesUpdateOK() *PaymentSignaturesUpdateOK {
	return &PaymentSignaturesUpdateOK{}
}

/*
PaymentSignaturesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type PaymentSignaturesUpdateOK struct {
	Payload *models.PaymentSignature
}

// IsSuccess returns true when this payment signatures update o k response has a 2xx status code
func (o *PaymentSignaturesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment signatures update o k response has a 3xx status code
func (o *PaymentSignaturesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment signatures update o k response has a 4xx status code
func (o *PaymentSignaturesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment signatures update o k response has a 5xx status code
func (o *PaymentSignaturesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment signatures update o k response a status code equal to that given
func (o *PaymentSignaturesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment signatures update o k response
func (o *PaymentSignaturesUpdateOK) Code() int {
	return 200
}

func (o *PaymentSignaturesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/Payment/Signatures/{paymentSignatureId}][%d] paymentSignaturesUpdateOK %s", 200, payload)
}

func (o *PaymentSignaturesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/Payment/Signatures/{paymentSignatureId}][%d] paymentSignaturesUpdateOK %s", 200, payload)
}

func (o *PaymentSignaturesUpdateOK) GetPayload() *models.PaymentSignature {
	return o.Payload
}

func (o *PaymentSignaturesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PaymentSignature)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentSignaturesUpdateDefault creates a PaymentSignaturesUpdateDefault with default headers values
func NewPaymentSignaturesUpdateDefault(code int) *PaymentSignaturesUpdateDefault {
	return &PaymentSignaturesUpdateDefault{
		_statusCode: code,
	}
}

/*
PaymentSignaturesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentSignaturesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment signatures update default response has a 2xx status code
func (o *PaymentSignaturesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment signatures update default response has a 3xx status code
func (o *PaymentSignaturesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment signatures update default response has a 4xx status code
func (o *PaymentSignaturesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment signatures update default response has a 5xx status code
func (o *PaymentSignaturesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment signatures update default response a status code equal to that given
func (o *PaymentSignaturesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment signatures update default response
func (o *PaymentSignaturesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *PaymentSignaturesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/Payment/Signatures/{paymentSignatureId}][%d] PaymentSignatures_Update default %s", o._statusCode, payload)
}

func (o *PaymentSignaturesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/Payment/Signatures/{paymentSignatureId}][%d] PaymentSignatures_Update default %s", o._statusCode, payload)
}

func (o *PaymentSignaturesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentSignaturesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}