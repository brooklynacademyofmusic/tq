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

// PriceTypeUserGroupsUpdateReader is a Reader for the PriceTypeUserGroupsUpdate structure.
type PriceTypeUserGroupsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PriceTypeUserGroupsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPriceTypeUserGroupsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPriceTypeUserGroupsUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPriceTypeUserGroupsUpdateOK creates a PriceTypeUserGroupsUpdateOK with default headers values
func NewPriceTypeUserGroupsUpdateOK() *PriceTypeUserGroupsUpdateOK {
	return &PriceTypeUserGroupsUpdateOK{}
}

/*
PriceTypeUserGroupsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type PriceTypeUserGroupsUpdateOK struct {
	Payload *models.PriceTypeUserGroup
}

// IsSuccess returns true when this price type user groups update o k response has a 2xx status code
func (o *PriceTypeUserGroupsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this price type user groups update o k response has a 3xx status code
func (o *PriceTypeUserGroupsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this price type user groups update o k response has a 4xx status code
func (o *PriceTypeUserGroupsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this price type user groups update o k response has a 5xx status code
func (o *PriceTypeUserGroupsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this price type user groups update o k response a status code equal to that given
func (o *PriceTypeUserGroupsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the price type user groups update o k response
func (o *PriceTypeUserGroupsUpdateOK) Code() int {
	return 200
}

func (o *PriceTypeUserGroupsUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/PriceTypeUserGroups/{priceTypeUserGroupId}][%d] priceTypeUserGroupsUpdateOK %s", 200, payload)
}

func (o *PriceTypeUserGroupsUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/PriceTypeUserGroups/{priceTypeUserGroupId}][%d] priceTypeUserGroupsUpdateOK %s", 200, payload)
}

func (o *PriceTypeUserGroupsUpdateOK) GetPayload() *models.PriceTypeUserGroup {
	return o.Payload
}

func (o *PriceTypeUserGroupsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PriceTypeUserGroup)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPriceTypeUserGroupsUpdateDefault creates a PriceTypeUserGroupsUpdateDefault with default headers values
func NewPriceTypeUserGroupsUpdateDefault(code int) *PriceTypeUserGroupsUpdateDefault {
	return &PriceTypeUserGroupsUpdateDefault{
		_statusCode: code,
	}
}

/*
PriceTypeUserGroupsUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type PriceTypeUserGroupsUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this price type user groups update default response has a 2xx status code
func (o *PriceTypeUserGroupsUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this price type user groups update default response has a 3xx status code
func (o *PriceTypeUserGroupsUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this price type user groups update default response has a 4xx status code
func (o *PriceTypeUserGroupsUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this price type user groups update default response has a 5xx status code
func (o *PriceTypeUserGroupsUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this price type user groups update default response a status code equal to that given
func (o *PriceTypeUserGroupsUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the price type user groups update default response
func (o *PriceTypeUserGroupsUpdateDefault) Code() int {
	return o._statusCode
}

func (o *PriceTypeUserGroupsUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/PriceTypeUserGroups/{priceTypeUserGroupId}][%d] PriceTypeUserGroups_Update default %s", o._statusCode, payload)
}

func (o *PriceTypeUserGroupsUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/PriceTypeUserGroups/{priceTypeUserGroupId}][%d] PriceTypeUserGroups_Update default %s", o._statusCode, payload)
}

func (o *PriceTypeUserGroupsUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PriceTypeUserGroupsUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}