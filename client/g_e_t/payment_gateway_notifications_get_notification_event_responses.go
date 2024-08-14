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

// PaymentGatewayNotificationsGetNotificationEventReader is a Reader for the PaymentGatewayNotificationsGetNotificationEvent structure.
type PaymentGatewayNotificationsGetNotificationEventReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentGatewayNotificationsGetNotificationEventReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentGatewayNotificationsGetNotificationEventOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentGatewayNotificationsGetNotificationEventDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentGatewayNotificationsGetNotificationEventOK creates a PaymentGatewayNotificationsGetNotificationEventOK with default headers values
func NewPaymentGatewayNotificationsGetNotificationEventOK() *PaymentGatewayNotificationsGetNotificationEventOK {
	return &PaymentGatewayNotificationsGetNotificationEventOK{}
}

/*
PaymentGatewayNotificationsGetNotificationEventOK describes a response with status code 200, with default header values.

OK
*/
type PaymentGatewayNotificationsGetNotificationEventOK struct {
	Payload *models.NotificationEvent
}

// IsSuccess returns true when this payment gateway notifications get notification event o k response has a 2xx status code
func (o *PaymentGatewayNotificationsGetNotificationEventOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment gateway notifications get notification event o k response has a 3xx status code
func (o *PaymentGatewayNotificationsGetNotificationEventOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment gateway notifications get notification event o k response has a 4xx status code
func (o *PaymentGatewayNotificationsGetNotificationEventOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment gateway notifications get notification event o k response has a 5xx status code
func (o *PaymentGatewayNotificationsGetNotificationEventOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment gateway notifications get notification event o k response a status code equal to that given
func (o *PaymentGatewayNotificationsGetNotificationEventOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment gateway notifications get notification event o k response
func (o *PaymentGatewayNotificationsGetNotificationEventOK) Code() int {
	return 200
}

func (o *PaymentGatewayNotificationsGetNotificationEventOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /PaymentGateway/Notifications/Events/{notificationEventId}][%d] paymentGatewayNotificationsGetNotificationEventOK %s", 200, payload)
}

func (o *PaymentGatewayNotificationsGetNotificationEventOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /PaymentGateway/Notifications/Events/{notificationEventId}][%d] paymentGatewayNotificationsGetNotificationEventOK %s", 200, payload)
}

func (o *PaymentGatewayNotificationsGetNotificationEventOK) GetPayload() *models.NotificationEvent {
	return o.Payload
}

func (o *PaymentGatewayNotificationsGetNotificationEventOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.NotificationEvent)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentGatewayNotificationsGetNotificationEventDefault creates a PaymentGatewayNotificationsGetNotificationEventDefault with default headers values
func NewPaymentGatewayNotificationsGetNotificationEventDefault(code int) *PaymentGatewayNotificationsGetNotificationEventDefault {
	return &PaymentGatewayNotificationsGetNotificationEventDefault{
		_statusCode: code,
	}
}

/*
PaymentGatewayNotificationsGetNotificationEventDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentGatewayNotificationsGetNotificationEventDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment gateway notifications get notification event default response has a 2xx status code
func (o *PaymentGatewayNotificationsGetNotificationEventDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment gateway notifications get notification event default response has a 3xx status code
func (o *PaymentGatewayNotificationsGetNotificationEventDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment gateway notifications get notification event default response has a 4xx status code
func (o *PaymentGatewayNotificationsGetNotificationEventDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment gateway notifications get notification event default response has a 5xx status code
func (o *PaymentGatewayNotificationsGetNotificationEventDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment gateway notifications get notification event default response a status code equal to that given
func (o *PaymentGatewayNotificationsGetNotificationEventDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment gateway notifications get notification event default response
func (o *PaymentGatewayNotificationsGetNotificationEventDefault) Code() int {
	return o._statusCode
}

func (o *PaymentGatewayNotificationsGetNotificationEventDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /PaymentGateway/Notifications/Events/{notificationEventId}][%d] PaymentGatewayNotifications_GetNotificationEvent default %s", o._statusCode, payload)
}

func (o *PaymentGatewayNotificationsGetNotificationEventDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /PaymentGateway/Notifications/Events/{notificationEventId}][%d] PaymentGatewayNotifications_GetNotificationEvent default %s", o._statusCode, payload)
}

func (o *PaymentGatewayNotificationsGetNotificationEventDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentGatewayNotificationsGetNotificationEventDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}