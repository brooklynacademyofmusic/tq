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

// CartUpdateSubLineItemPriceReader is a Reader for the CartUpdateSubLineItemPrice structure.
type CartUpdateSubLineItemPriceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CartUpdateSubLineItemPriceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCartUpdateSubLineItemPriceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCartUpdateSubLineItemPriceDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCartUpdateSubLineItemPriceOK creates a CartUpdateSubLineItemPriceOK with default headers values
func NewCartUpdateSubLineItemPriceOK() *CartUpdateSubLineItemPriceOK {
	return &CartUpdateSubLineItemPriceOK{}
}

/*
CartUpdateSubLineItemPriceOK describes a response with status code 200, with default header values.

OK
*/
type CartUpdateSubLineItemPriceOK struct {
	Payload *models.UpdatePriceResponse
}

// IsSuccess returns true when this cart update sub line item price o k response has a 2xx status code
func (o *CartUpdateSubLineItemPriceOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cart update sub line item price o k response has a 3xx status code
func (o *CartUpdateSubLineItemPriceOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cart update sub line item price o k response has a 4xx status code
func (o *CartUpdateSubLineItemPriceOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this cart update sub line item price o k response has a 5xx status code
func (o *CartUpdateSubLineItemPriceOK) IsServerError() bool {
	return false
}

// IsCode returns true when this cart update sub line item price o k response a status code equal to that given
func (o *CartUpdateSubLineItemPriceOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the cart update sub line item price o k response
func (o *CartUpdateSubLineItemPriceOK) Code() int {
	return 200
}

func (o *CartUpdateSubLineItemPriceOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/SubLineItems/{subLineItemId}/Price][%d] cartUpdateSubLineItemPriceOK %s", 200, payload)
}

func (o *CartUpdateSubLineItemPriceOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/SubLineItems/{subLineItemId}/Price][%d] cartUpdateSubLineItemPriceOK %s", 200, payload)
}

func (o *CartUpdateSubLineItemPriceOK) GetPayload() *models.UpdatePriceResponse {
	return o.Payload
}

func (o *CartUpdateSubLineItemPriceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UpdatePriceResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCartUpdateSubLineItemPriceDefault creates a CartUpdateSubLineItemPriceDefault with default headers values
func NewCartUpdateSubLineItemPriceDefault(code int) *CartUpdateSubLineItemPriceDefault {
	return &CartUpdateSubLineItemPriceDefault{
		_statusCode: code,
	}
}

/*
CartUpdateSubLineItemPriceDefault describes a response with status code -1, with default header values.

Error
*/
type CartUpdateSubLineItemPriceDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this cart update sub line item price default response has a 2xx status code
func (o *CartUpdateSubLineItemPriceDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this cart update sub line item price default response has a 3xx status code
func (o *CartUpdateSubLineItemPriceDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this cart update sub line item price default response has a 4xx status code
func (o *CartUpdateSubLineItemPriceDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this cart update sub line item price default response has a 5xx status code
func (o *CartUpdateSubLineItemPriceDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this cart update sub line item price default response a status code equal to that given
func (o *CartUpdateSubLineItemPriceDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the cart update sub line item price default response
func (o *CartUpdateSubLineItemPriceDefault) Code() int {
	return o._statusCode
}

func (o *CartUpdateSubLineItemPriceDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/SubLineItems/{subLineItemId}/Price][%d] Cart_UpdateSubLineItemPrice default %s", o._statusCode, payload)
}

func (o *CartUpdateSubLineItemPriceDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/SubLineItems/{subLineItemId}/Price][%d] Cart_UpdateSubLineItemPrice default %s", o._statusCode, payload)
}

func (o *CartUpdateSubLineItemPriceDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CartUpdateSubLineItemPriceDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}