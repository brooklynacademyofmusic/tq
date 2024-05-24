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

// PaymentMethodGroupsDeleteReader is a Reader for the PaymentMethodGroupsDelete structure.
type PaymentMethodGroupsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentMethodGroupsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPaymentMethodGroupsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentMethodGroupsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentMethodGroupsDeleteNoContent creates a PaymentMethodGroupsDeleteNoContent with default headers values
func NewPaymentMethodGroupsDeleteNoContent() *PaymentMethodGroupsDeleteNoContent {
	return &PaymentMethodGroupsDeleteNoContent{}
}

/*
PaymentMethodGroupsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type PaymentMethodGroupsDeleteNoContent struct {
}

// IsSuccess returns true when this payment method groups delete no content response has a 2xx status code
func (o *PaymentMethodGroupsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment method groups delete no content response has a 3xx status code
func (o *PaymentMethodGroupsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment method groups delete no content response has a 4xx status code
func (o *PaymentMethodGroupsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment method groups delete no content response has a 5xx status code
func (o *PaymentMethodGroupsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this payment method groups delete no content response a status code equal to that given
func (o *PaymentMethodGroupsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the payment method groups delete no content response
func (o *PaymentMethodGroupsDeleteNoContent) Code() int {
	return 204
}

func (o *PaymentMethodGroupsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/PaymentMethodGroups/{id}][%d] paymentMethodGroupsDeleteNoContent", 204)
}

func (o *PaymentMethodGroupsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/PaymentMethodGroups/{id}][%d] paymentMethodGroupsDeleteNoContent", 204)
}

func (o *PaymentMethodGroupsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPaymentMethodGroupsDeleteDefault creates a PaymentMethodGroupsDeleteDefault with default headers values
func NewPaymentMethodGroupsDeleteDefault(code int) *PaymentMethodGroupsDeleteDefault {
	return &PaymentMethodGroupsDeleteDefault{
		_statusCode: code,
	}
}

/*
PaymentMethodGroupsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentMethodGroupsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment method groups delete default response has a 2xx status code
func (o *PaymentMethodGroupsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment method groups delete default response has a 3xx status code
func (o *PaymentMethodGroupsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment method groups delete default response has a 4xx status code
func (o *PaymentMethodGroupsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment method groups delete default response has a 5xx status code
func (o *PaymentMethodGroupsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment method groups delete default response a status code equal to that given
func (o *PaymentMethodGroupsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment method groups delete default response
func (o *PaymentMethodGroupsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *PaymentMethodGroupsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/PaymentMethodGroups/{id}][%d] PaymentMethodGroups_Delete default %s", o._statusCode, payload)
}

func (o *PaymentMethodGroupsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/PaymentMethodGroups/{id}][%d] PaymentMethodGroups_Delete default %s", o._statusCode, payload)
}

func (o *PaymentMethodGroupsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentMethodGroupsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
