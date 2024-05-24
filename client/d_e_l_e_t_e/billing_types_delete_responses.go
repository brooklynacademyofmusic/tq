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

// BillingTypesDeleteReader is a Reader for the BillingTypesDelete structure.
type BillingTypesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BillingTypesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewBillingTypesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewBillingTypesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewBillingTypesDeleteNoContent creates a BillingTypesDeleteNoContent with default headers values
func NewBillingTypesDeleteNoContent() *BillingTypesDeleteNoContent {
	return &BillingTypesDeleteNoContent{}
}

/*
BillingTypesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type BillingTypesDeleteNoContent struct {
}

// IsSuccess returns true when this billing types delete no content response has a 2xx status code
func (o *BillingTypesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this billing types delete no content response has a 3xx status code
func (o *BillingTypesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this billing types delete no content response has a 4xx status code
func (o *BillingTypesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this billing types delete no content response has a 5xx status code
func (o *BillingTypesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this billing types delete no content response a status code equal to that given
func (o *BillingTypesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the billing types delete no content response
func (o *BillingTypesDeleteNoContent) Code() int {
	return 204
}

func (o *BillingTypesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/BillingTypes/{id}][%d] billingTypesDeleteNoContent", 204)
}

func (o *BillingTypesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/BillingTypes/{id}][%d] billingTypesDeleteNoContent", 204)
}

func (o *BillingTypesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewBillingTypesDeleteDefault creates a BillingTypesDeleteDefault with default headers values
func NewBillingTypesDeleteDefault(code int) *BillingTypesDeleteDefault {
	return &BillingTypesDeleteDefault{
		_statusCode: code,
	}
}

/*
BillingTypesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type BillingTypesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this billing types delete default response has a 2xx status code
func (o *BillingTypesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this billing types delete default response has a 3xx status code
func (o *BillingTypesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this billing types delete default response has a 4xx status code
func (o *BillingTypesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this billing types delete default response has a 5xx status code
func (o *BillingTypesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this billing types delete default response a status code equal to that given
func (o *BillingTypesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the billing types delete default response
func (o *BillingTypesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *BillingTypesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/BillingTypes/{id}][%d] BillingTypes_Delete default %s", o._statusCode, payload)
}

func (o *BillingTypesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/BillingTypes/{id}][%d] BillingTypes_Delete default %s", o._statusCode, payload)
}

func (o *BillingTypesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *BillingTypesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
