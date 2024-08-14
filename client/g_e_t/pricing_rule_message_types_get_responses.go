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

// PricingRuleMessageTypesGetReader is a Reader for the PricingRuleMessageTypesGet structure.
type PricingRuleMessageTypesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PricingRuleMessageTypesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPricingRuleMessageTypesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPricingRuleMessageTypesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPricingRuleMessageTypesGetOK creates a PricingRuleMessageTypesGetOK with default headers values
func NewPricingRuleMessageTypesGetOK() *PricingRuleMessageTypesGetOK {
	return &PricingRuleMessageTypesGetOK{}
}

/*
PricingRuleMessageTypesGetOK describes a response with status code 200, with default header values.

OK
*/
type PricingRuleMessageTypesGetOK struct {
	Payload *models.PricingRuleMessageType
}

// IsSuccess returns true when this pricing rule message types get o k response has a 2xx status code
func (o *PricingRuleMessageTypesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this pricing rule message types get o k response has a 3xx status code
func (o *PricingRuleMessageTypesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pricing rule message types get o k response has a 4xx status code
func (o *PricingRuleMessageTypesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this pricing rule message types get o k response has a 5xx status code
func (o *PricingRuleMessageTypesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this pricing rule message types get o k response a status code equal to that given
func (o *PricingRuleMessageTypesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the pricing rule message types get o k response
func (o *PricingRuleMessageTypesGetOK) Code() int {
	return 200
}

func (o *PricingRuleMessageTypesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PricingRuleMessageTypes/{id}][%d] pricingRuleMessageTypesGetOK %s", 200, payload)
}

func (o *PricingRuleMessageTypesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PricingRuleMessageTypes/{id}][%d] pricingRuleMessageTypesGetOK %s", 200, payload)
}

func (o *PricingRuleMessageTypesGetOK) GetPayload() *models.PricingRuleMessageType {
	return o.Payload
}

func (o *PricingRuleMessageTypesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PricingRuleMessageType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPricingRuleMessageTypesGetDefault creates a PricingRuleMessageTypesGetDefault with default headers values
func NewPricingRuleMessageTypesGetDefault(code int) *PricingRuleMessageTypesGetDefault {
	return &PricingRuleMessageTypesGetDefault{
		_statusCode: code,
	}
}

/*
PricingRuleMessageTypesGetDefault describes a response with status code -1, with default header values.

Error
*/
type PricingRuleMessageTypesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this pricing rule message types get default response has a 2xx status code
func (o *PricingRuleMessageTypesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this pricing rule message types get default response has a 3xx status code
func (o *PricingRuleMessageTypesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this pricing rule message types get default response has a 4xx status code
func (o *PricingRuleMessageTypesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this pricing rule message types get default response has a 5xx status code
func (o *PricingRuleMessageTypesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this pricing rule message types get default response a status code equal to that given
func (o *PricingRuleMessageTypesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the pricing rule message types get default response
func (o *PricingRuleMessageTypesGetDefault) Code() int {
	return o._statusCode
}

func (o *PricingRuleMessageTypesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PricingRuleMessageTypes/{id}][%d] PricingRuleMessageTypes_Get default %s", o._statusCode, payload)
}

func (o *PricingRuleMessageTypesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PricingRuleMessageTypes/{id}][%d] PricingRuleMessageTypes_Get default %s", o._statusCode, payload)
}

func (o *PricingRuleMessageTypesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PricingRuleMessageTypesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}