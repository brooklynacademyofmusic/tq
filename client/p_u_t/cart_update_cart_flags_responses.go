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

// CartUpdateCartFlagsReader is a Reader for the CartUpdateCartFlags structure.
type CartUpdateCartFlagsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CartUpdateCartFlagsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCartUpdateCartFlagsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCartUpdateCartFlagsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCartUpdateCartFlagsOK creates a CartUpdateCartFlagsOK with default headers values
func NewCartUpdateCartFlagsOK() *CartUpdateCartFlagsOK {
	return &CartUpdateCartFlagsOK{}
}

/*
CartUpdateCartFlagsOK describes a response with status code 200, with default header values.

OK
*/
type CartUpdateCartFlagsOK struct {
	Payload *models.CartFlags
}

// IsSuccess returns true when this cart update cart flags o k response has a 2xx status code
func (o *CartUpdateCartFlagsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cart update cart flags o k response has a 3xx status code
func (o *CartUpdateCartFlagsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cart update cart flags o k response has a 4xx status code
func (o *CartUpdateCartFlagsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this cart update cart flags o k response has a 5xx status code
func (o *CartUpdateCartFlagsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this cart update cart flags o k response a status code equal to that given
func (o *CartUpdateCartFlagsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the cart update cart flags o k response
func (o *CartUpdateCartFlagsOK) Code() int {
	return 200
}

func (o *CartUpdateCartFlagsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/CartFlags][%d] cartUpdateCartFlagsOK %s", 200, payload)
}

func (o *CartUpdateCartFlagsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/CartFlags][%d] cartUpdateCartFlagsOK %s", 200, payload)
}

func (o *CartUpdateCartFlagsOK) GetPayload() *models.CartFlags {
	return o.Payload
}

func (o *CartUpdateCartFlagsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CartFlags)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCartUpdateCartFlagsDefault creates a CartUpdateCartFlagsDefault with default headers values
func NewCartUpdateCartFlagsDefault(code int) *CartUpdateCartFlagsDefault {
	return &CartUpdateCartFlagsDefault{
		_statusCode: code,
	}
}

/*
CartUpdateCartFlagsDefault describes a response with status code -1, with default header values.

Error
*/
type CartUpdateCartFlagsDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this cart update cart flags default response has a 2xx status code
func (o *CartUpdateCartFlagsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this cart update cart flags default response has a 3xx status code
func (o *CartUpdateCartFlagsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this cart update cart flags default response has a 4xx status code
func (o *CartUpdateCartFlagsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this cart update cart flags default response has a 5xx status code
func (o *CartUpdateCartFlagsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this cart update cart flags default response a status code equal to that given
func (o *CartUpdateCartFlagsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the cart update cart flags default response
func (o *CartUpdateCartFlagsDefault) Code() int {
	return o._statusCode
}

func (o *CartUpdateCartFlagsDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/CartFlags][%d] Cart_UpdateCartFlags default %s", o._statusCode, payload)
}

func (o *CartUpdateCartFlagsDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/CartFlags][%d] Cart_UpdateCartFlags default %s", o._statusCode, payload)
}

func (o *CartUpdateCartFlagsDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CartUpdateCartFlagsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
