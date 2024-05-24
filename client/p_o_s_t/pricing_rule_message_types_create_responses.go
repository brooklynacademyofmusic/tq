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

// PricingRuleMessageTypesCreateReader is a Reader for the PricingRuleMessageTypesCreate structure.
type PricingRuleMessageTypesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PricingRuleMessageTypesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPricingRuleMessageTypesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPricingRuleMessageTypesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPricingRuleMessageTypesCreateOK creates a PricingRuleMessageTypesCreateOK with default headers values
func NewPricingRuleMessageTypesCreateOK() *PricingRuleMessageTypesCreateOK {
	return &PricingRuleMessageTypesCreateOK{}
}

/*
PricingRuleMessageTypesCreateOK describes a response with status code 200, with default header values.

OK
*/
type PricingRuleMessageTypesCreateOK struct {
	Payload *models.PricingRuleMessageType
}

// IsSuccess returns true when this pricing rule message types create o k response has a 2xx status code
func (o *PricingRuleMessageTypesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this pricing rule message types create o k response has a 3xx status code
func (o *PricingRuleMessageTypesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pricing rule message types create o k response has a 4xx status code
func (o *PricingRuleMessageTypesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this pricing rule message types create o k response has a 5xx status code
func (o *PricingRuleMessageTypesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this pricing rule message types create o k response a status code equal to that given
func (o *PricingRuleMessageTypesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the pricing rule message types create o k response
func (o *PricingRuleMessageTypesCreateOK) Code() int {
	return 200
}

func (o *PricingRuleMessageTypesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PricingRuleMessageTypes][%d] pricingRuleMessageTypesCreateOK %s", 200, payload)
}

func (o *PricingRuleMessageTypesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PricingRuleMessageTypes][%d] pricingRuleMessageTypesCreateOK %s", 200, payload)
}

func (o *PricingRuleMessageTypesCreateOK) GetPayload() *models.PricingRuleMessageType {
	return o.Payload
}

func (o *PricingRuleMessageTypesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PricingRuleMessageType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPricingRuleMessageTypesCreateDefault creates a PricingRuleMessageTypesCreateDefault with default headers values
func NewPricingRuleMessageTypesCreateDefault(code int) *PricingRuleMessageTypesCreateDefault {
	return &PricingRuleMessageTypesCreateDefault{
		_statusCode: code,
	}
}

/*
PricingRuleMessageTypesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type PricingRuleMessageTypesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this pricing rule message types create default response has a 2xx status code
func (o *PricingRuleMessageTypesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this pricing rule message types create default response has a 3xx status code
func (o *PricingRuleMessageTypesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this pricing rule message types create default response has a 4xx status code
func (o *PricingRuleMessageTypesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this pricing rule message types create default response has a 5xx status code
func (o *PricingRuleMessageTypesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this pricing rule message types create default response a status code equal to that given
func (o *PricingRuleMessageTypesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the pricing rule message types create default response
func (o *PricingRuleMessageTypesCreateDefault) Code() int {
	return o._statusCode
}

func (o *PricingRuleMessageTypesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PricingRuleMessageTypes][%d] PricingRuleMessageTypes_Create default %s", o._statusCode, payload)
}

func (o *PricingRuleMessageTypesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PricingRuleMessageTypes][%d] PricingRuleMessageTypes_Create default %s", o._statusCode, payload)
}

func (o *PricingRuleMessageTypesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PricingRuleMessageTypesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
