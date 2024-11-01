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

// PaymentMethodGroupsGetAllReader is a Reader for the PaymentMethodGroupsGetAll structure.
type PaymentMethodGroupsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentMethodGroupsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentMethodGroupsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentMethodGroupsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentMethodGroupsGetAllOK creates a PaymentMethodGroupsGetAllOK with default headers values
func NewPaymentMethodGroupsGetAllOK() *PaymentMethodGroupsGetAllOK {
	return &PaymentMethodGroupsGetAllOK{}
}

/*
PaymentMethodGroupsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type PaymentMethodGroupsGetAllOK struct {
	Payload []*models.PaymentMethodGroup
}

// IsSuccess returns true when this payment method groups get all o k response has a 2xx status code
func (o *PaymentMethodGroupsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment method groups get all o k response has a 3xx status code
func (o *PaymentMethodGroupsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment method groups get all o k response has a 4xx status code
func (o *PaymentMethodGroupsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment method groups get all o k response has a 5xx status code
func (o *PaymentMethodGroupsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment method groups get all o k response a status code equal to that given
func (o *PaymentMethodGroupsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment method groups get all o k response
func (o *PaymentMethodGroupsGetAllOK) Code() int {
	return 200
}

func (o *PaymentMethodGroupsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PaymentMethodGroups][%d] paymentMethodGroupsGetAllOK %s", 200, payload)
}

func (o *PaymentMethodGroupsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PaymentMethodGroups][%d] paymentMethodGroupsGetAllOK %s", 200, payload)
}

func (o *PaymentMethodGroupsGetAllOK) GetPayload() []*models.PaymentMethodGroup {
	return o.Payload
}

func (o *PaymentMethodGroupsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentMethodGroupsGetAllDefault creates a PaymentMethodGroupsGetAllDefault with default headers values
func NewPaymentMethodGroupsGetAllDefault(code int) *PaymentMethodGroupsGetAllDefault {
	return &PaymentMethodGroupsGetAllDefault{
		_statusCode: code,
	}
}

/*
PaymentMethodGroupsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentMethodGroupsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment method groups get all default response has a 2xx status code
func (o *PaymentMethodGroupsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment method groups get all default response has a 3xx status code
func (o *PaymentMethodGroupsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment method groups get all default response has a 4xx status code
func (o *PaymentMethodGroupsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment method groups get all default response has a 5xx status code
func (o *PaymentMethodGroupsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment method groups get all default response a status code equal to that given
func (o *PaymentMethodGroupsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment method groups get all default response
func (o *PaymentMethodGroupsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *PaymentMethodGroupsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PaymentMethodGroups][%d] PaymentMethodGroups_GetAll default %s", o._statusCode, payload)
}

func (o *PaymentMethodGroupsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PaymentMethodGroups][%d] PaymentMethodGroups_GetAll default %s", o._statusCode, payload)
}

func (o *PaymentMethodGroupsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentMethodGroupsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}