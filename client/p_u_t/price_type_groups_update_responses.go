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

// PriceTypeGroupsUpdateReader is a Reader for the PriceTypeGroupsUpdate structure.
type PriceTypeGroupsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PriceTypeGroupsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPriceTypeGroupsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPriceTypeGroupsUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPriceTypeGroupsUpdateOK creates a PriceTypeGroupsUpdateOK with default headers values
func NewPriceTypeGroupsUpdateOK() *PriceTypeGroupsUpdateOK {
	return &PriceTypeGroupsUpdateOK{}
}

/*
PriceTypeGroupsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type PriceTypeGroupsUpdateOK struct {
	Payload *models.PriceTypeGroup
}

// IsSuccess returns true when this price type groups update o k response has a 2xx status code
func (o *PriceTypeGroupsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this price type groups update o k response has a 3xx status code
func (o *PriceTypeGroupsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this price type groups update o k response has a 4xx status code
func (o *PriceTypeGroupsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this price type groups update o k response has a 5xx status code
func (o *PriceTypeGroupsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this price type groups update o k response a status code equal to that given
func (o *PriceTypeGroupsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the price type groups update o k response
func (o *PriceTypeGroupsUpdateOK) Code() int {
	return 200
}

func (o *PriceTypeGroupsUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/PriceTypeGroups/{id}][%d] priceTypeGroupsUpdateOK %s", 200, payload)
}

func (o *PriceTypeGroupsUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/PriceTypeGroups/{id}][%d] priceTypeGroupsUpdateOK %s", 200, payload)
}

func (o *PriceTypeGroupsUpdateOK) GetPayload() *models.PriceTypeGroup {
	return o.Payload
}

func (o *PriceTypeGroupsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PriceTypeGroup)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPriceTypeGroupsUpdateDefault creates a PriceTypeGroupsUpdateDefault with default headers values
func NewPriceTypeGroupsUpdateDefault(code int) *PriceTypeGroupsUpdateDefault {
	return &PriceTypeGroupsUpdateDefault{
		_statusCode: code,
	}
}

/*
PriceTypeGroupsUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type PriceTypeGroupsUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this price type groups update default response has a 2xx status code
func (o *PriceTypeGroupsUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this price type groups update default response has a 3xx status code
func (o *PriceTypeGroupsUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this price type groups update default response has a 4xx status code
func (o *PriceTypeGroupsUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this price type groups update default response has a 5xx status code
func (o *PriceTypeGroupsUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this price type groups update default response a status code equal to that given
func (o *PriceTypeGroupsUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the price type groups update default response
func (o *PriceTypeGroupsUpdateDefault) Code() int {
	return o._statusCode
}

func (o *PriceTypeGroupsUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/PriceTypeGroups/{id}][%d] PriceTypeGroups_Update default %s", o._statusCode, payload)
}

func (o *PriceTypeGroupsUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/PriceTypeGroups/{id}][%d] PriceTypeGroups_Update default %s", o._statusCode, payload)
}

func (o *PriceTypeGroupsUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PriceTypeGroupsUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
