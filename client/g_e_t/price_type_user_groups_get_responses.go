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

// PriceTypeUserGroupsGetReader is a Reader for the PriceTypeUserGroupsGet structure.
type PriceTypeUserGroupsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PriceTypeUserGroupsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPriceTypeUserGroupsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPriceTypeUserGroupsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPriceTypeUserGroupsGetOK creates a PriceTypeUserGroupsGetOK with default headers values
func NewPriceTypeUserGroupsGetOK() *PriceTypeUserGroupsGetOK {
	return &PriceTypeUserGroupsGetOK{}
}

/*
PriceTypeUserGroupsGetOK describes a response with status code 200, with default header values.

OK
*/
type PriceTypeUserGroupsGetOK struct {
	Payload *models.PriceTypeUserGroup
}

// IsSuccess returns true when this price type user groups get o k response has a 2xx status code
func (o *PriceTypeUserGroupsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this price type user groups get o k response has a 3xx status code
func (o *PriceTypeUserGroupsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this price type user groups get o k response has a 4xx status code
func (o *PriceTypeUserGroupsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this price type user groups get o k response has a 5xx status code
func (o *PriceTypeUserGroupsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this price type user groups get o k response a status code equal to that given
func (o *PriceTypeUserGroupsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the price type user groups get o k response
func (o *PriceTypeUserGroupsGetOK) Code() int {
	return 200
}

func (o *PriceTypeUserGroupsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypeUserGroups/{priceTypeUserGroupId}][%d] priceTypeUserGroupsGetOK %s", 200, payload)
}

func (o *PriceTypeUserGroupsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypeUserGroups/{priceTypeUserGroupId}][%d] priceTypeUserGroupsGetOK %s", 200, payload)
}

func (o *PriceTypeUserGroupsGetOK) GetPayload() *models.PriceTypeUserGroup {
	return o.Payload
}

func (o *PriceTypeUserGroupsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PriceTypeUserGroup)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPriceTypeUserGroupsGetDefault creates a PriceTypeUserGroupsGetDefault with default headers values
func NewPriceTypeUserGroupsGetDefault(code int) *PriceTypeUserGroupsGetDefault {
	return &PriceTypeUserGroupsGetDefault{
		_statusCode: code,
	}
}

/*
PriceTypeUserGroupsGetDefault describes a response with status code -1, with default header values.

Error
*/
type PriceTypeUserGroupsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this price type user groups get default response has a 2xx status code
func (o *PriceTypeUserGroupsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this price type user groups get default response has a 3xx status code
func (o *PriceTypeUserGroupsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this price type user groups get default response has a 4xx status code
func (o *PriceTypeUserGroupsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this price type user groups get default response has a 5xx status code
func (o *PriceTypeUserGroupsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this price type user groups get default response a status code equal to that given
func (o *PriceTypeUserGroupsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the price type user groups get default response
func (o *PriceTypeUserGroupsGetDefault) Code() int {
	return o._statusCode
}

func (o *PriceTypeUserGroupsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypeUserGroups/{priceTypeUserGroupId}][%d] PriceTypeUserGroups_Get default %s", o._statusCode, payload)
}

func (o *PriceTypeUserGroupsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypeUserGroups/{priceTypeUserGroupId}][%d] PriceTypeUserGroups_Get default %s", o._statusCode, payload)
}

func (o *PriceTypeUserGroupsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PriceTypeUserGroupsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
