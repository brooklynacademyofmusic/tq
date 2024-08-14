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

// PricingRuleCategoriesGetReader is a Reader for the PricingRuleCategoriesGet structure.
type PricingRuleCategoriesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PricingRuleCategoriesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPricingRuleCategoriesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPricingRuleCategoriesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPricingRuleCategoriesGetOK creates a PricingRuleCategoriesGetOK with default headers values
func NewPricingRuleCategoriesGetOK() *PricingRuleCategoriesGetOK {
	return &PricingRuleCategoriesGetOK{}
}

/*
PricingRuleCategoriesGetOK describes a response with status code 200, with default header values.

OK
*/
type PricingRuleCategoriesGetOK struct {
	Payload *models.PricingRuleCategory
}

// IsSuccess returns true when this pricing rule categories get o k response has a 2xx status code
func (o *PricingRuleCategoriesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this pricing rule categories get o k response has a 3xx status code
func (o *PricingRuleCategoriesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pricing rule categories get o k response has a 4xx status code
func (o *PricingRuleCategoriesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this pricing rule categories get o k response has a 5xx status code
func (o *PricingRuleCategoriesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this pricing rule categories get o k response a status code equal to that given
func (o *PricingRuleCategoriesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the pricing rule categories get o k response
func (o *PricingRuleCategoriesGetOK) Code() int {
	return 200
}

func (o *PricingRuleCategoriesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PricingRuleCategories/{id}][%d] pricingRuleCategoriesGetOK %s", 200, payload)
}

func (o *PricingRuleCategoriesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PricingRuleCategories/{id}][%d] pricingRuleCategoriesGetOK %s", 200, payload)
}

func (o *PricingRuleCategoriesGetOK) GetPayload() *models.PricingRuleCategory {
	return o.Payload
}

func (o *PricingRuleCategoriesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PricingRuleCategory)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPricingRuleCategoriesGetDefault creates a PricingRuleCategoriesGetDefault with default headers values
func NewPricingRuleCategoriesGetDefault(code int) *PricingRuleCategoriesGetDefault {
	return &PricingRuleCategoriesGetDefault{
		_statusCode: code,
	}
}

/*
PricingRuleCategoriesGetDefault describes a response with status code -1, with default header values.

Error
*/
type PricingRuleCategoriesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this pricing rule categories get default response has a 2xx status code
func (o *PricingRuleCategoriesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this pricing rule categories get default response has a 3xx status code
func (o *PricingRuleCategoriesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this pricing rule categories get default response has a 4xx status code
func (o *PricingRuleCategoriesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this pricing rule categories get default response has a 5xx status code
func (o *PricingRuleCategoriesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this pricing rule categories get default response a status code equal to that given
func (o *PricingRuleCategoriesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the pricing rule categories get default response
func (o *PricingRuleCategoriesGetDefault) Code() int {
	return o._statusCode
}

func (o *PricingRuleCategoriesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PricingRuleCategories/{id}][%d] PricingRuleCategories_Get default %s", o._statusCode, payload)
}

func (o *PricingRuleCategoriesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PricingRuleCategories/{id}][%d] PricingRuleCategories_Get default %s", o._statusCode, payload)
}

func (o *PricingRuleCategoriesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PricingRuleCategoriesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}