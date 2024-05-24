// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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

// PriceTypesDeleteReader is a Reader for the PriceTypesDelete structure.
type PriceTypesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PriceTypesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPriceTypesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPriceTypesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPriceTypesDeleteNoContent creates a PriceTypesDeleteNoContent with default headers values
func NewPriceTypesDeleteNoContent() *PriceTypesDeleteNoContent {
	return &PriceTypesDeleteNoContent{}
}

/*
PriceTypesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type PriceTypesDeleteNoContent struct {
}

// IsSuccess returns true when this price types delete no content response has a 2xx status code
func (o *PriceTypesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this price types delete no content response has a 3xx status code
func (o *PriceTypesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this price types delete no content response has a 4xx status code
func (o *PriceTypesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this price types delete no content response has a 5xx status code
func (o *PriceTypesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this price types delete no content response a status code equal to that given
func (o *PriceTypesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the price types delete no content response
func (o *PriceTypesDeleteNoContent) Code() int {
	return 204
}

func (o *PriceTypesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /TXN/PriceTypes/{priceTypeId}][%d] priceTypesDeleteNoContent", 204)
}

func (o *PriceTypesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /TXN/PriceTypes/{priceTypeId}][%d] priceTypesDeleteNoContent", 204)
}

func (o *PriceTypesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPriceTypesDeleteDefault creates a PriceTypesDeleteDefault with default headers values
func NewPriceTypesDeleteDefault(code int) *PriceTypesDeleteDefault {
	return &PriceTypesDeleteDefault{
		_statusCode: code,
	}
}

/*
PriceTypesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type PriceTypesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this price types delete default response has a 2xx status code
func (o *PriceTypesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this price types delete default response has a 3xx status code
func (o *PriceTypesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this price types delete default response has a 4xx status code
func (o *PriceTypesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this price types delete default response has a 5xx status code
func (o *PriceTypesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this price types delete default response a status code equal to that given
func (o *PriceTypesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the price types delete default response
func (o *PriceTypesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *PriceTypesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PriceTypes/{priceTypeId}][%d] PriceTypes_Delete default %s", o._statusCode, payload)
}

func (o *PriceTypesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PriceTypes/{priceTypeId}][%d] PriceTypes_Delete default %s", o._statusCode, payload)
}

func (o *PriceTypesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PriceTypesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
