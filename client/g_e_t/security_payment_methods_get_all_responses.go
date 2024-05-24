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

// SecurityPaymentMethodsGetAllReader is a Reader for the SecurityPaymentMethodsGetAll structure.
type SecurityPaymentMethodsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SecurityPaymentMethodsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSecurityPaymentMethodsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSecurityPaymentMethodsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSecurityPaymentMethodsGetAllOK creates a SecurityPaymentMethodsGetAllOK with default headers values
func NewSecurityPaymentMethodsGetAllOK() *SecurityPaymentMethodsGetAllOK {
	return &SecurityPaymentMethodsGetAllOK{}
}

/*
SecurityPaymentMethodsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type SecurityPaymentMethodsGetAllOK struct {
	Payload []*models.PaymentMethodUserGroup
}

// IsSuccess returns true when this security payment methods get all o k response has a 2xx status code
func (o *SecurityPaymentMethodsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this security payment methods get all o k response has a 3xx status code
func (o *SecurityPaymentMethodsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this security payment methods get all o k response has a 4xx status code
func (o *SecurityPaymentMethodsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this security payment methods get all o k response has a 5xx status code
func (o *SecurityPaymentMethodsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this security payment methods get all o k response a status code equal to that given
func (o *SecurityPaymentMethodsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the security payment methods get all o k response
func (o *SecurityPaymentMethodsGetAllOK) Code() int {
	return 200
}

func (o *SecurityPaymentMethodsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/PaymentMethods][%d] securityPaymentMethodsGetAllOK %s", 200, payload)
}

func (o *SecurityPaymentMethodsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/PaymentMethods][%d] securityPaymentMethodsGetAllOK %s", 200, payload)
}

func (o *SecurityPaymentMethodsGetAllOK) GetPayload() []*models.PaymentMethodUserGroup {
	return o.Payload
}

func (o *SecurityPaymentMethodsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSecurityPaymentMethodsGetAllDefault creates a SecurityPaymentMethodsGetAllDefault with default headers values
func NewSecurityPaymentMethodsGetAllDefault(code int) *SecurityPaymentMethodsGetAllDefault {
	return &SecurityPaymentMethodsGetAllDefault{
		_statusCode: code,
	}
}

/*
SecurityPaymentMethodsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type SecurityPaymentMethodsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this security payment methods get all default response has a 2xx status code
func (o *SecurityPaymentMethodsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this security payment methods get all default response has a 3xx status code
func (o *SecurityPaymentMethodsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this security payment methods get all default response has a 4xx status code
func (o *SecurityPaymentMethodsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this security payment methods get all default response has a 5xx status code
func (o *SecurityPaymentMethodsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this security payment methods get all default response a status code equal to that given
func (o *SecurityPaymentMethodsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the security payment methods get all default response
func (o *SecurityPaymentMethodsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *SecurityPaymentMethodsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/PaymentMethods][%d] SecurityPaymentMethods_GetAll default %s", o._statusCode, payload)
}

func (o *SecurityPaymentMethodsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/PaymentMethods][%d] SecurityPaymentMethods_GetAll default %s", o._statusCode, payload)
}

func (o *SecurityPaymentMethodsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SecurityPaymentMethodsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
