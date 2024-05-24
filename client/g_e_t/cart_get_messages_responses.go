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

// CartGetMessagesReader is a Reader for the CartGetMessages structure.
type CartGetMessagesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CartGetMessagesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCartGetMessagesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCartGetMessagesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCartGetMessagesOK creates a CartGetMessagesOK with default headers values
func NewCartGetMessagesOK() *CartGetMessagesOK {
	return &CartGetMessagesOK{}
}

/*
CartGetMessagesOK describes a response with status code 200, with default header values.

OK
*/
type CartGetMessagesOK struct {
	Payload []*models.CartPricingRuleMessage
}

// IsSuccess returns true when this cart get messages o k response has a 2xx status code
func (o *CartGetMessagesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cart get messages o k response has a 3xx status code
func (o *CartGetMessagesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cart get messages o k response has a 4xx status code
func (o *CartGetMessagesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this cart get messages o k response has a 5xx status code
func (o *CartGetMessagesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this cart get messages o k response a status code equal to that given
func (o *CartGetMessagesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the cart get messages o k response
func (o *CartGetMessagesOK) Code() int {
	return 200
}

func (o *CartGetMessagesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Web/Cart/{sessionKey}/Messages][%d] cartGetMessagesOK %s", 200, payload)
}

func (o *CartGetMessagesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Web/Cart/{sessionKey}/Messages][%d] cartGetMessagesOK %s", 200, payload)
}

func (o *CartGetMessagesOK) GetPayload() []*models.CartPricingRuleMessage {
	return o.Payload
}

func (o *CartGetMessagesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCartGetMessagesDefault creates a CartGetMessagesDefault with default headers values
func NewCartGetMessagesDefault(code int) *CartGetMessagesDefault {
	return &CartGetMessagesDefault{
		_statusCode: code,
	}
}

/*
CartGetMessagesDefault describes a response with status code -1, with default header values.

Error
*/
type CartGetMessagesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this cart get messages default response has a 2xx status code
func (o *CartGetMessagesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this cart get messages default response has a 3xx status code
func (o *CartGetMessagesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this cart get messages default response has a 4xx status code
func (o *CartGetMessagesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this cart get messages default response has a 5xx status code
func (o *CartGetMessagesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this cart get messages default response a status code equal to that given
func (o *CartGetMessagesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the cart get messages default response
func (o *CartGetMessagesDefault) Code() int {
	return o._statusCode
}

func (o *CartGetMessagesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Web/Cart/{sessionKey}/Messages][%d] Cart_GetMessages default %s", o._statusCode, payload)
}

func (o *CartGetMessagesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Web/Cart/{sessionKey}/Messages][%d] Cart_GetMessages default %s", o._statusCode, payload)
}

func (o *CartGetMessagesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CartGetMessagesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
