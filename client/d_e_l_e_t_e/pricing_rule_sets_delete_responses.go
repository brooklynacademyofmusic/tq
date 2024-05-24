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

// PricingRuleSetsDeleteReader is a Reader for the PricingRuleSetsDelete structure.
type PricingRuleSetsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PricingRuleSetsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPricingRuleSetsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPricingRuleSetsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPricingRuleSetsDeleteNoContent creates a PricingRuleSetsDeleteNoContent with default headers values
func NewPricingRuleSetsDeleteNoContent() *PricingRuleSetsDeleteNoContent {
	return &PricingRuleSetsDeleteNoContent{}
}

/*
PricingRuleSetsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type PricingRuleSetsDeleteNoContent struct {
}

// IsSuccess returns true when this pricing rule sets delete no content response has a 2xx status code
func (o *PricingRuleSetsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this pricing rule sets delete no content response has a 3xx status code
func (o *PricingRuleSetsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pricing rule sets delete no content response has a 4xx status code
func (o *PricingRuleSetsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this pricing rule sets delete no content response has a 5xx status code
func (o *PricingRuleSetsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this pricing rule sets delete no content response a status code equal to that given
func (o *PricingRuleSetsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the pricing rule sets delete no content response
func (o *PricingRuleSetsDeleteNoContent) Code() int {
	return 204
}

func (o *PricingRuleSetsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /TXN/PricingRuleSets/{pricingRuleSetId}][%d] pricingRuleSetsDeleteNoContent", 204)
}

func (o *PricingRuleSetsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /TXN/PricingRuleSets/{pricingRuleSetId}][%d] pricingRuleSetsDeleteNoContent", 204)
}

func (o *PricingRuleSetsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPricingRuleSetsDeleteDefault creates a PricingRuleSetsDeleteDefault with default headers values
func NewPricingRuleSetsDeleteDefault(code int) *PricingRuleSetsDeleteDefault {
	return &PricingRuleSetsDeleteDefault{
		_statusCode: code,
	}
}

/*
PricingRuleSetsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type PricingRuleSetsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this pricing rule sets delete default response has a 2xx status code
func (o *PricingRuleSetsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this pricing rule sets delete default response has a 3xx status code
func (o *PricingRuleSetsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this pricing rule sets delete default response has a 4xx status code
func (o *PricingRuleSetsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this pricing rule sets delete default response has a 5xx status code
func (o *PricingRuleSetsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this pricing rule sets delete default response a status code equal to that given
func (o *PricingRuleSetsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the pricing rule sets delete default response
func (o *PricingRuleSetsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *PricingRuleSetsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PricingRuleSets/{pricingRuleSetId}][%d] PricingRuleSets_Delete default %s", o._statusCode, payload)
}

func (o *PricingRuleSetsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PricingRuleSets/{pricingRuleSetId}][%d] PricingRuleSets_Delete default %s", o._statusCode, payload)
}

func (o *PricingRuleSetsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PricingRuleSetsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
