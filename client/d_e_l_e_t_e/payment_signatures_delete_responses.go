// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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

// PaymentSignaturesDeleteReader is a Reader for the PaymentSignaturesDelete structure.
type PaymentSignaturesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentSignaturesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPaymentSignaturesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentSignaturesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentSignaturesDeleteNoContent creates a PaymentSignaturesDeleteNoContent with default headers values
func NewPaymentSignaturesDeleteNoContent() *PaymentSignaturesDeleteNoContent {
	return &PaymentSignaturesDeleteNoContent{}
}

/*
PaymentSignaturesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type PaymentSignaturesDeleteNoContent struct {
}

// IsSuccess returns true when this payment signatures delete no content response has a 2xx status code
func (o *PaymentSignaturesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment signatures delete no content response has a 3xx status code
func (o *PaymentSignaturesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment signatures delete no content response has a 4xx status code
func (o *PaymentSignaturesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment signatures delete no content response has a 5xx status code
func (o *PaymentSignaturesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this payment signatures delete no content response a status code equal to that given
func (o *PaymentSignaturesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the payment signatures delete no content response
func (o *PaymentSignaturesDeleteNoContent) Code() int {
	return 204
}

func (o *PaymentSignaturesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /TXN/Payment/Signatures/{paymentSignatureId}][%d] paymentSignaturesDeleteNoContent", 204)
}

func (o *PaymentSignaturesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /TXN/Payment/Signatures/{paymentSignatureId}][%d] paymentSignaturesDeleteNoContent", 204)
}

func (o *PaymentSignaturesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPaymentSignaturesDeleteDefault creates a PaymentSignaturesDeleteDefault with default headers values
func NewPaymentSignaturesDeleteDefault(code int) *PaymentSignaturesDeleteDefault {
	return &PaymentSignaturesDeleteDefault{
		_statusCode: code,
	}
}

/*
PaymentSignaturesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentSignaturesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment signatures delete default response has a 2xx status code
func (o *PaymentSignaturesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment signatures delete default response has a 3xx status code
func (o *PaymentSignaturesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment signatures delete default response has a 4xx status code
func (o *PaymentSignaturesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment signatures delete default response has a 5xx status code
func (o *PaymentSignaturesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment signatures delete default response a status code equal to that given
func (o *PaymentSignaturesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment signatures delete default response
func (o *PaymentSignaturesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *PaymentSignaturesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/Payment/Signatures/{paymentSignatureId}][%d] PaymentSignatures_Delete default %s", o._statusCode, payload)
}

func (o *PaymentSignaturesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/Payment/Signatures/{paymentSignatureId}][%d] PaymentSignatures_Delete default %s", o._statusCode, payload)
}

func (o *PaymentSignaturesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentSignaturesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
