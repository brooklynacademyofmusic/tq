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

// CartApplyLineItemDiscountReader is a Reader for the CartApplyLineItemDiscount structure.
type CartApplyLineItemDiscountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CartApplyLineItemDiscountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCartApplyLineItemDiscountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCartApplyLineItemDiscountDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCartApplyLineItemDiscountOK creates a CartApplyLineItemDiscountOK with default headers values
func NewCartApplyLineItemDiscountOK() *CartApplyLineItemDiscountOK {
	return &CartApplyLineItemDiscountOK{}
}

/*
CartApplyLineItemDiscountOK describes a response with status code 200, with default header values.

OK
*/
type CartApplyLineItemDiscountOK struct {
	Payload []*models.UpdatePriceResponse
}

// IsSuccess returns true when this cart apply line item discount o k response has a 2xx status code
func (o *CartApplyLineItemDiscountOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cart apply line item discount o k response has a 3xx status code
func (o *CartApplyLineItemDiscountOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cart apply line item discount o k response has a 4xx status code
func (o *CartApplyLineItemDiscountOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this cart apply line item discount o k response has a 5xx status code
func (o *CartApplyLineItemDiscountOK) IsServerError() bool {
	return false
}

// IsCode returns true when this cart apply line item discount o k response a status code equal to that given
func (o *CartApplyLineItemDiscountOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the cart apply line item discount o k response
func (o *CartApplyLineItemDiscountOK) Code() int {
	return 200
}

func (o *CartApplyLineItemDiscountOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/LineItems/{lineItemId}/Discount][%d] cartApplyLineItemDiscountOK %s", 200, payload)
}

func (o *CartApplyLineItemDiscountOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/LineItems/{lineItemId}/Discount][%d] cartApplyLineItemDiscountOK %s", 200, payload)
}

func (o *CartApplyLineItemDiscountOK) GetPayload() []*models.UpdatePriceResponse {
	return o.Payload
}

func (o *CartApplyLineItemDiscountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCartApplyLineItemDiscountDefault creates a CartApplyLineItemDiscountDefault with default headers values
func NewCartApplyLineItemDiscountDefault(code int) *CartApplyLineItemDiscountDefault {
	return &CartApplyLineItemDiscountDefault{
		_statusCode: code,
	}
}

/*
CartApplyLineItemDiscountDefault describes a response with status code -1, with default header values.

Error
*/
type CartApplyLineItemDiscountDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this cart apply line item discount default response has a 2xx status code
func (o *CartApplyLineItemDiscountDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this cart apply line item discount default response has a 3xx status code
func (o *CartApplyLineItemDiscountDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this cart apply line item discount default response has a 4xx status code
func (o *CartApplyLineItemDiscountDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this cart apply line item discount default response has a 5xx status code
func (o *CartApplyLineItemDiscountDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this cart apply line item discount default response a status code equal to that given
func (o *CartApplyLineItemDiscountDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the cart apply line item discount default response
func (o *CartApplyLineItemDiscountDefault) Code() int {
	return o._statusCode
}

func (o *CartApplyLineItemDiscountDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/LineItems/{lineItemId}/Discount][%d] Cart_ApplyLineItemDiscount default %s", o._statusCode, payload)
}

func (o *CartApplyLineItemDiscountDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Cart/{sessionKey}/LineItems/{lineItemId}/Discount][%d] Cart_ApplyLineItemDiscount default %s", o._statusCode, payload)
}

func (o *CartApplyLineItemDiscountDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CartApplyLineItemDiscountDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}