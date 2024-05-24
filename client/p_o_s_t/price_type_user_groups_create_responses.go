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

// PriceTypeUserGroupsCreateReader is a Reader for the PriceTypeUserGroupsCreate structure.
type PriceTypeUserGroupsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PriceTypeUserGroupsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPriceTypeUserGroupsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPriceTypeUserGroupsCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPriceTypeUserGroupsCreateOK creates a PriceTypeUserGroupsCreateOK with default headers values
func NewPriceTypeUserGroupsCreateOK() *PriceTypeUserGroupsCreateOK {
	return &PriceTypeUserGroupsCreateOK{}
}

/*
PriceTypeUserGroupsCreateOK describes a response with status code 200, with default header values.

OK
*/
type PriceTypeUserGroupsCreateOK struct {
	Payload *models.PriceTypeUserGroup
}

// IsSuccess returns true when this price type user groups create o k response has a 2xx status code
func (o *PriceTypeUserGroupsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this price type user groups create o k response has a 3xx status code
func (o *PriceTypeUserGroupsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this price type user groups create o k response has a 4xx status code
func (o *PriceTypeUserGroupsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this price type user groups create o k response has a 5xx status code
func (o *PriceTypeUserGroupsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this price type user groups create o k response a status code equal to that given
func (o *PriceTypeUserGroupsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the price type user groups create o k response
func (o *PriceTypeUserGroupsCreateOK) Code() int {
	return 200
}

func (o *PriceTypeUserGroupsCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/PriceTypeUserGroups][%d] priceTypeUserGroupsCreateOK %s", 200, payload)
}

func (o *PriceTypeUserGroupsCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/PriceTypeUserGroups][%d] priceTypeUserGroupsCreateOK %s", 200, payload)
}

func (o *PriceTypeUserGroupsCreateOK) GetPayload() *models.PriceTypeUserGroup {
	return o.Payload
}

func (o *PriceTypeUserGroupsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PriceTypeUserGroup)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPriceTypeUserGroupsCreateDefault creates a PriceTypeUserGroupsCreateDefault with default headers values
func NewPriceTypeUserGroupsCreateDefault(code int) *PriceTypeUserGroupsCreateDefault {
	return &PriceTypeUserGroupsCreateDefault{
		_statusCode: code,
	}
}

/*
PriceTypeUserGroupsCreateDefault describes a response with status code -1, with default header values.

Error
*/
type PriceTypeUserGroupsCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this price type user groups create default response has a 2xx status code
func (o *PriceTypeUserGroupsCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this price type user groups create default response has a 3xx status code
func (o *PriceTypeUserGroupsCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this price type user groups create default response has a 4xx status code
func (o *PriceTypeUserGroupsCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this price type user groups create default response has a 5xx status code
func (o *PriceTypeUserGroupsCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this price type user groups create default response a status code equal to that given
func (o *PriceTypeUserGroupsCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the price type user groups create default response
func (o *PriceTypeUserGroupsCreateDefault) Code() int {
	return o._statusCode
}

func (o *PriceTypeUserGroupsCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/PriceTypeUserGroups][%d] PriceTypeUserGroups_Create default %s", o._statusCode, payload)
}

func (o *PriceTypeUserGroupsCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/PriceTypeUserGroups][%d] PriceTypeUserGroups_Create default %s", o._statusCode, payload)
}

func (o *PriceTypeUserGroupsCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PriceTypeUserGroupsCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
