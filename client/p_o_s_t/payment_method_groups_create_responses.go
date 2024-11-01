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

// PaymentMethodGroupsCreateReader is a Reader for the PaymentMethodGroupsCreate structure.
type PaymentMethodGroupsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentMethodGroupsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentMethodGroupsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentMethodGroupsCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentMethodGroupsCreateOK creates a PaymentMethodGroupsCreateOK with default headers values
func NewPaymentMethodGroupsCreateOK() *PaymentMethodGroupsCreateOK {
	return &PaymentMethodGroupsCreateOK{}
}

/*
PaymentMethodGroupsCreateOK describes a response with status code 200, with default header values.

OK
*/
type PaymentMethodGroupsCreateOK struct {
	Payload *models.PaymentMethodGroup
}

// IsSuccess returns true when this payment method groups create o k response has a 2xx status code
func (o *PaymentMethodGroupsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment method groups create o k response has a 3xx status code
func (o *PaymentMethodGroupsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment method groups create o k response has a 4xx status code
func (o *PaymentMethodGroupsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment method groups create o k response has a 5xx status code
func (o *PaymentMethodGroupsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment method groups create o k response a status code equal to that given
func (o *PaymentMethodGroupsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment method groups create o k response
func (o *PaymentMethodGroupsCreateOK) Code() int {
	return 200
}

func (o *PaymentMethodGroupsCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PaymentMethodGroups][%d] paymentMethodGroupsCreateOK %s", 200, payload)
}

func (o *PaymentMethodGroupsCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PaymentMethodGroups][%d] paymentMethodGroupsCreateOK %s", 200, payload)
}

func (o *PaymentMethodGroupsCreateOK) GetPayload() *models.PaymentMethodGroup {
	return o.Payload
}

func (o *PaymentMethodGroupsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PaymentMethodGroup)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentMethodGroupsCreateDefault creates a PaymentMethodGroupsCreateDefault with default headers values
func NewPaymentMethodGroupsCreateDefault(code int) *PaymentMethodGroupsCreateDefault {
	return &PaymentMethodGroupsCreateDefault{
		_statusCode: code,
	}
}

/*
PaymentMethodGroupsCreateDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentMethodGroupsCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment method groups create default response has a 2xx status code
func (o *PaymentMethodGroupsCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment method groups create default response has a 3xx status code
func (o *PaymentMethodGroupsCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment method groups create default response has a 4xx status code
func (o *PaymentMethodGroupsCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment method groups create default response has a 5xx status code
func (o *PaymentMethodGroupsCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment method groups create default response a status code equal to that given
func (o *PaymentMethodGroupsCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment method groups create default response
func (o *PaymentMethodGroupsCreateDefault) Code() int {
	return o._statusCode
}

func (o *PaymentMethodGroupsCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PaymentMethodGroups][%d] PaymentMethodGroups_Create default %s", o._statusCode, payload)
}

func (o *PaymentMethodGroupsCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PaymentMethodGroups][%d] PaymentMethodGroups_Create default %s", o._statusCode, payload)
}

func (o *PaymentMethodGroupsCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentMethodGroupsCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}