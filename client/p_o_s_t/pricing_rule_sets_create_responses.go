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

// PricingRuleSetsCreateReader is a Reader for the PricingRuleSetsCreate structure.
type PricingRuleSetsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PricingRuleSetsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPricingRuleSetsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPricingRuleSetsCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPricingRuleSetsCreateOK creates a PricingRuleSetsCreateOK with default headers values
func NewPricingRuleSetsCreateOK() *PricingRuleSetsCreateOK {
	return &PricingRuleSetsCreateOK{}
}

/*
PricingRuleSetsCreateOK describes a response with status code 200, with default header values.

OK
*/
type PricingRuleSetsCreateOK struct {
	Payload *models.PricingRuleSet
}

// IsSuccess returns true when this pricing rule sets create o k response has a 2xx status code
func (o *PricingRuleSetsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this pricing rule sets create o k response has a 3xx status code
func (o *PricingRuleSetsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pricing rule sets create o k response has a 4xx status code
func (o *PricingRuleSetsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this pricing rule sets create o k response has a 5xx status code
func (o *PricingRuleSetsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this pricing rule sets create o k response a status code equal to that given
func (o *PricingRuleSetsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the pricing rule sets create o k response
func (o *PricingRuleSetsCreateOK) Code() int {
	return 200
}

func (o *PricingRuleSetsCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/PricingRuleSets][%d] pricingRuleSetsCreateOK %s", 200, payload)
}

func (o *PricingRuleSetsCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/PricingRuleSets][%d] pricingRuleSetsCreateOK %s", 200, payload)
}

func (o *PricingRuleSetsCreateOK) GetPayload() *models.PricingRuleSet {
	return o.Payload
}

func (o *PricingRuleSetsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PricingRuleSet)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPricingRuleSetsCreateDefault creates a PricingRuleSetsCreateDefault with default headers values
func NewPricingRuleSetsCreateDefault(code int) *PricingRuleSetsCreateDefault {
	return &PricingRuleSetsCreateDefault{
		_statusCode: code,
	}
}

/*
PricingRuleSetsCreateDefault describes a response with status code -1, with default header values.

Error
*/
type PricingRuleSetsCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this pricing rule sets create default response has a 2xx status code
func (o *PricingRuleSetsCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this pricing rule sets create default response has a 3xx status code
func (o *PricingRuleSetsCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this pricing rule sets create default response has a 4xx status code
func (o *PricingRuleSetsCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this pricing rule sets create default response has a 5xx status code
func (o *PricingRuleSetsCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this pricing rule sets create default response a status code equal to that given
func (o *PricingRuleSetsCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the pricing rule sets create default response
func (o *PricingRuleSetsCreateDefault) Code() int {
	return o._statusCode
}

func (o *PricingRuleSetsCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/PricingRuleSets][%d] PricingRuleSets_Create default %s", o._statusCode, payload)
}

func (o *PricingRuleSetsCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/PricingRuleSets][%d] PricingRuleSets_Create default %s", o._statusCode, payload)
}

func (o *PricingRuleSetsCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PricingRuleSetsCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
