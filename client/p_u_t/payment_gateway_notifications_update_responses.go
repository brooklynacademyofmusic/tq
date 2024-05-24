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

// PaymentGatewayNotificationsUpdateReader is a Reader for the PaymentGatewayNotificationsUpdate structure.
type PaymentGatewayNotificationsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentGatewayNotificationsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentGatewayNotificationsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentGatewayNotificationsUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentGatewayNotificationsUpdateOK creates a PaymentGatewayNotificationsUpdateOK with default headers values
func NewPaymentGatewayNotificationsUpdateOK() *PaymentGatewayNotificationsUpdateOK {
	return &PaymentGatewayNotificationsUpdateOK{}
}

/*
PaymentGatewayNotificationsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type PaymentGatewayNotificationsUpdateOK struct {
	Payload *models.NotificationEvent
}

// IsSuccess returns true when this payment gateway notifications update o k response has a 2xx status code
func (o *PaymentGatewayNotificationsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment gateway notifications update o k response has a 3xx status code
func (o *PaymentGatewayNotificationsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment gateway notifications update o k response has a 4xx status code
func (o *PaymentGatewayNotificationsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment gateway notifications update o k response has a 5xx status code
func (o *PaymentGatewayNotificationsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment gateway notifications update o k response a status code equal to that given
func (o *PaymentGatewayNotificationsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment gateway notifications update o k response
func (o *PaymentGatewayNotificationsUpdateOK) Code() int {
	return 200
}

func (o *PaymentGatewayNotificationsUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /PaymentGateway/Notifications/Events/{notificationEventId}][%d] paymentGatewayNotificationsUpdateOK %s", 200, payload)
}

func (o *PaymentGatewayNotificationsUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /PaymentGateway/Notifications/Events/{notificationEventId}][%d] paymentGatewayNotificationsUpdateOK %s", 200, payload)
}

func (o *PaymentGatewayNotificationsUpdateOK) GetPayload() *models.NotificationEvent {
	return o.Payload
}

func (o *PaymentGatewayNotificationsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.NotificationEvent)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentGatewayNotificationsUpdateDefault creates a PaymentGatewayNotificationsUpdateDefault with default headers values
func NewPaymentGatewayNotificationsUpdateDefault(code int) *PaymentGatewayNotificationsUpdateDefault {
	return &PaymentGatewayNotificationsUpdateDefault{
		_statusCode: code,
	}
}

/*
PaymentGatewayNotificationsUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentGatewayNotificationsUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment gateway notifications update default response has a 2xx status code
func (o *PaymentGatewayNotificationsUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment gateway notifications update default response has a 3xx status code
func (o *PaymentGatewayNotificationsUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment gateway notifications update default response has a 4xx status code
func (o *PaymentGatewayNotificationsUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment gateway notifications update default response has a 5xx status code
func (o *PaymentGatewayNotificationsUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment gateway notifications update default response a status code equal to that given
func (o *PaymentGatewayNotificationsUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment gateway notifications update default response
func (o *PaymentGatewayNotificationsUpdateDefault) Code() int {
	return o._statusCode
}

func (o *PaymentGatewayNotificationsUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /PaymentGateway/Notifications/Events/{notificationEventId}][%d] PaymentGatewayNotifications_Update default %s", o._statusCode, payload)
}

func (o *PaymentGatewayNotificationsUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /PaymentGateway/Notifications/Events/{notificationEventId}][%d] PaymentGatewayNotifications_Update default %s", o._statusCode, payload)
}

func (o *PaymentGatewayNotificationsUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentGatewayNotificationsUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
