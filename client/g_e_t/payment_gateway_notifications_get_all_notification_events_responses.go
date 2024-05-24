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

// PaymentGatewayNotificationsGetAllNotificationEventsReader is a Reader for the PaymentGatewayNotificationsGetAllNotificationEvents structure.
type PaymentGatewayNotificationsGetAllNotificationEventsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentGatewayNotificationsGetAllNotificationEventsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentGatewayNotificationsGetAllNotificationEventsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentGatewayNotificationsGetAllNotificationEventsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentGatewayNotificationsGetAllNotificationEventsOK creates a PaymentGatewayNotificationsGetAllNotificationEventsOK with default headers values
func NewPaymentGatewayNotificationsGetAllNotificationEventsOK() *PaymentGatewayNotificationsGetAllNotificationEventsOK {
	return &PaymentGatewayNotificationsGetAllNotificationEventsOK{}
}

/*
PaymentGatewayNotificationsGetAllNotificationEventsOK describes a response with status code 200, with default header values.

OK
*/
type PaymentGatewayNotificationsGetAllNotificationEventsOK struct {
	Payload []*models.NotificationEvent
}

// IsSuccess returns true when this payment gateway notifications get all notification events o k response has a 2xx status code
func (o *PaymentGatewayNotificationsGetAllNotificationEventsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment gateway notifications get all notification events o k response has a 3xx status code
func (o *PaymentGatewayNotificationsGetAllNotificationEventsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment gateway notifications get all notification events o k response has a 4xx status code
func (o *PaymentGatewayNotificationsGetAllNotificationEventsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment gateway notifications get all notification events o k response has a 5xx status code
func (o *PaymentGatewayNotificationsGetAllNotificationEventsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment gateway notifications get all notification events o k response a status code equal to that given
func (o *PaymentGatewayNotificationsGetAllNotificationEventsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment gateway notifications get all notification events o k response
func (o *PaymentGatewayNotificationsGetAllNotificationEventsOK) Code() int {
	return 200
}

func (o *PaymentGatewayNotificationsGetAllNotificationEventsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /PaymentGateway/Notifications/Events][%d] paymentGatewayNotificationsGetAllNotificationEventsOK %s", 200, payload)
}

func (o *PaymentGatewayNotificationsGetAllNotificationEventsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /PaymentGateway/Notifications/Events][%d] paymentGatewayNotificationsGetAllNotificationEventsOK %s", 200, payload)
}

func (o *PaymentGatewayNotificationsGetAllNotificationEventsOK) GetPayload() []*models.NotificationEvent {
	return o.Payload
}

func (o *PaymentGatewayNotificationsGetAllNotificationEventsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentGatewayNotificationsGetAllNotificationEventsDefault creates a PaymentGatewayNotificationsGetAllNotificationEventsDefault with default headers values
func NewPaymentGatewayNotificationsGetAllNotificationEventsDefault(code int) *PaymentGatewayNotificationsGetAllNotificationEventsDefault {
	return &PaymentGatewayNotificationsGetAllNotificationEventsDefault{
		_statusCode: code,
	}
}

/*
PaymentGatewayNotificationsGetAllNotificationEventsDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentGatewayNotificationsGetAllNotificationEventsDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment gateway notifications get all notification events default response has a 2xx status code
func (o *PaymentGatewayNotificationsGetAllNotificationEventsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment gateway notifications get all notification events default response has a 3xx status code
func (o *PaymentGatewayNotificationsGetAllNotificationEventsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment gateway notifications get all notification events default response has a 4xx status code
func (o *PaymentGatewayNotificationsGetAllNotificationEventsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment gateway notifications get all notification events default response has a 5xx status code
func (o *PaymentGatewayNotificationsGetAllNotificationEventsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment gateway notifications get all notification events default response a status code equal to that given
func (o *PaymentGatewayNotificationsGetAllNotificationEventsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment gateway notifications get all notification events default response
func (o *PaymentGatewayNotificationsGetAllNotificationEventsDefault) Code() int {
	return o._statusCode
}

func (o *PaymentGatewayNotificationsGetAllNotificationEventsDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /PaymentGateway/Notifications/Events][%d] PaymentGatewayNotifications_GetAllNotificationEvents default %s", o._statusCode, payload)
}

func (o *PaymentGatewayNotificationsGetAllNotificationEventsDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /PaymentGateway/Notifications/Events][%d] PaymentGatewayNotifications_GetAllNotificationEvents default %s", o._statusCode, payload)
}

func (o *PaymentGatewayNotificationsGetAllNotificationEventsDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentGatewayNotificationsGetAllNotificationEventsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
