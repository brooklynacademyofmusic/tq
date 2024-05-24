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

// PaymentGatewayCredentialsGetCredentialReader is a Reader for the PaymentGatewayCredentialsGetCredential structure.
type PaymentGatewayCredentialsGetCredentialReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentGatewayCredentialsGetCredentialReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentGatewayCredentialsGetCredentialOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentGatewayCredentialsGetCredentialDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentGatewayCredentialsGetCredentialOK creates a PaymentGatewayCredentialsGetCredentialOK with default headers values
func NewPaymentGatewayCredentialsGetCredentialOK() *PaymentGatewayCredentialsGetCredentialOK {
	return &PaymentGatewayCredentialsGetCredentialOK{}
}

/*
PaymentGatewayCredentialsGetCredentialOK describes a response with status code 200, with default header values.

OK
*/
type PaymentGatewayCredentialsGetCredentialOK struct {
	Payload *models.PaymentGatewayCredential
}

// IsSuccess returns true when this payment gateway credentials get credential o k response has a 2xx status code
func (o *PaymentGatewayCredentialsGetCredentialOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment gateway credentials get credential o k response has a 3xx status code
func (o *PaymentGatewayCredentialsGetCredentialOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment gateway credentials get credential o k response has a 4xx status code
func (o *PaymentGatewayCredentialsGetCredentialOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment gateway credentials get credential o k response has a 5xx status code
func (o *PaymentGatewayCredentialsGetCredentialOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment gateway credentials get credential o k response a status code equal to that given
func (o *PaymentGatewayCredentialsGetCredentialOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment gateway credentials get credential o k response
func (o *PaymentGatewayCredentialsGetCredentialOK) Code() int {
	return 200
}

func (o *PaymentGatewayCredentialsGetCredentialOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /PaymentGateway/Credentials][%d] paymentGatewayCredentialsGetCredentialOK %s", 200, payload)
}

func (o *PaymentGatewayCredentialsGetCredentialOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /PaymentGateway/Credentials][%d] paymentGatewayCredentialsGetCredentialOK %s", 200, payload)
}

func (o *PaymentGatewayCredentialsGetCredentialOK) GetPayload() *models.PaymentGatewayCredential {
	return o.Payload
}

func (o *PaymentGatewayCredentialsGetCredentialOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PaymentGatewayCredential)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentGatewayCredentialsGetCredentialDefault creates a PaymentGatewayCredentialsGetCredentialDefault with default headers values
func NewPaymentGatewayCredentialsGetCredentialDefault(code int) *PaymentGatewayCredentialsGetCredentialDefault {
	return &PaymentGatewayCredentialsGetCredentialDefault{
		_statusCode: code,
	}
}

/*
PaymentGatewayCredentialsGetCredentialDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentGatewayCredentialsGetCredentialDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment gateway credentials get credential default response has a 2xx status code
func (o *PaymentGatewayCredentialsGetCredentialDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment gateway credentials get credential default response has a 3xx status code
func (o *PaymentGatewayCredentialsGetCredentialDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment gateway credentials get credential default response has a 4xx status code
func (o *PaymentGatewayCredentialsGetCredentialDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment gateway credentials get credential default response has a 5xx status code
func (o *PaymentGatewayCredentialsGetCredentialDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment gateway credentials get credential default response a status code equal to that given
func (o *PaymentGatewayCredentialsGetCredentialDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment gateway credentials get credential default response
func (o *PaymentGatewayCredentialsGetCredentialDefault) Code() int {
	return o._statusCode
}

func (o *PaymentGatewayCredentialsGetCredentialDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /PaymentGateway/Credentials][%d] PaymentGatewayCredentials_GetCredential default %s", o._statusCode, payload)
}

func (o *PaymentGatewayCredentialsGetCredentialDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /PaymentGateway/Credentials][%d] PaymentGatewayCredentials_GetCredential default %s", o._statusCode, payload)
}

func (o *PaymentGatewayCredentialsGetCredentialDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentGatewayCredentialsGetCredentialDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
