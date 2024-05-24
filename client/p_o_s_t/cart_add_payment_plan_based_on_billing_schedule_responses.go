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

// CartAddPaymentPlanBasedOnBillingScheduleReader is a Reader for the CartAddPaymentPlanBasedOnBillingSchedule structure.
type CartAddPaymentPlanBasedOnBillingScheduleReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CartAddPaymentPlanBasedOnBillingScheduleReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCartAddPaymentPlanBasedOnBillingScheduleOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCartAddPaymentPlanBasedOnBillingScheduleDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCartAddPaymentPlanBasedOnBillingScheduleOK creates a CartAddPaymentPlanBasedOnBillingScheduleOK with default headers values
func NewCartAddPaymentPlanBasedOnBillingScheduleOK() *CartAddPaymentPlanBasedOnBillingScheduleOK {
	return &CartAddPaymentPlanBasedOnBillingScheduleOK{}
}

/*
CartAddPaymentPlanBasedOnBillingScheduleOK describes a response with status code 200, with default header values.

OK
*/
type CartAddPaymentPlanBasedOnBillingScheduleOK struct {
	Payload []*models.PaymentPlan
}

// IsSuccess returns true when this cart add payment plan based on billing schedule o k response has a 2xx status code
func (o *CartAddPaymentPlanBasedOnBillingScheduleOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cart add payment plan based on billing schedule o k response has a 3xx status code
func (o *CartAddPaymentPlanBasedOnBillingScheduleOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cart add payment plan based on billing schedule o k response has a 4xx status code
func (o *CartAddPaymentPlanBasedOnBillingScheduleOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this cart add payment plan based on billing schedule o k response has a 5xx status code
func (o *CartAddPaymentPlanBasedOnBillingScheduleOK) IsServerError() bool {
	return false
}

// IsCode returns true when this cart add payment plan based on billing schedule o k response a status code equal to that given
func (o *CartAddPaymentPlanBasedOnBillingScheduleOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the cart add payment plan based on billing schedule o k response
func (o *CartAddPaymentPlanBasedOnBillingScheduleOK) Code() int {
	return 200
}

func (o *CartAddPaymentPlanBasedOnBillingScheduleOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Web/Cart/{sessionKey}/Payments/Plan/Schedule][%d] cartAddPaymentPlanBasedOnBillingScheduleOK %s", 200, payload)
}

func (o *CartAddPaymentPlanBasedOnBillingScheduleOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Web/Cart/{sessionKey}/Payments/Plan/Schedule][%d] cartAddPaymentPlanBasedOnBillingScheduleOK %s", 200, payload)
}

func (o *CartAddPaymentPlanBasedOnBillingScheduleOK) GetPayload() []*models.PaymentPlan {
	return o.Payload
}

func (o *CartAddPaymentPlanBasedOnBillingScheduleOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCartAddPaymentPlanBasedOnBillingScheduleDefault creates a CartAddPaymentPlanBasedOnBillingScheduleDefault with default headers values
func NewCartAddPaymentPlanBasedOnBillingScheduleDefault(code int) *CartAddPaymentPlanBasedOnBillingScheduleDefault {
	return &CartAddPaymentPlanBasedOnBillingScheduleDefault{
		_statusCode: code,
	}
}

/*
CartAddPaymentPlanBasedOnBillingScheduleDefault describes a response with status code -1, with default header values.

Error
*/
type CartAddPaymentPlanBasedOnBillingScheduleDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this cart add payment plan based on billing schedule default response has a 2xx status code
func (o *CartAddPaymentPlanBasedOnBillingScheduleDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this cart add payment plan based on billing schedule default response has a 3xx status code
func (o *CartAddPaymentPlanBasedOnBillingScheduleDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this cart add payment plan based on billing schedule default response has a 4xx status code
func (o *CartAddPaymentPlanBasedOnBillingScheduleDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this cart add payment plan based on billing schedule default response has a 5xx status code
func (o *CartAddPaymentPlanBasedOnBillingScheduleDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this cart add payment plan based on billing schedule default response a status code equal to that given
func (o *CartAddPaymentPlanBasedOnBillingScheduleDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the cart add payment plan based on billing schedule default response
func (o *CartAddPaymentPlanBasedOnBillingScheduleDefault) Code() int {
	return o._statusCode
}

func (o *CartAddPaymentPlanBasedOnBillingScheduleDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Web/Cart/{sessionKey}/Payments/Plan/Schedule][%d] Cart_AddPaymentPlanBasedOnBillingSchedule default %s", o._statusCode, payload)
}

func (o *CartAddPaymentPlanBasedOnBillingScheduleDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Web/Cart/{sessionKey}/Payments/Plan/Schedule][%d] Cart_AddPaymentPlanBasedOnBillingSchedule default %s", o._statusCode, payload)
}

func (o *CartAddPaymentPlanBasedOnBillingScheduleDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CartAddPaymentPlanBasedOnBillingScheduleDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
