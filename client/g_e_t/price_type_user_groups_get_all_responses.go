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

// PriceTypeUserGroupsGetAllReader is a Reader for the PriceTypeUserGroupsGetAll structure.
type PriceTypeUserGroupsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PriceTypeUserGroupsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPriceTypeUserGroupsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPriceTypeUserGroupsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPriceTypeUserGroupsGetAllOK creates a PriceTypeUserGroupsGetAllOK with default headers values
func NewPriceTypeUserGroupsGetAllOK() *PriceTypeUserGroupsGetAllOK {
	return &PriceTypeUserGroupsGetAllOK{}
}

/*
PriceTypeUserGroupsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type PriceTypeUserGroupsGetAllOK struct {
	Payload []*models.PriceTypeUserGroup
}

// IsSuccess returns true when this price type user groups get all o k response has a 2xx status code
func (o *PriceTypeUserGroupsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this price type user groups get all o k response has a 3xx status code
func (o *PriceTypeUserGroupsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this price type user groups get all o k response has a 4xx status code
func (o *PriceTypeUserGroupsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this price type user groups get all o k response has a 5xx status code
func (o *PriceTypeUserGroupsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this price type user groups get all o k response a status code equal to that given
func (o *PriceTypeUserGroupsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the price type user groups get all o k response
func (o *PriceTypeUserGroupsGetAllOK) Code() int {
	return 200
}

func (o *PriceTypeUserGroupsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypeUserGroups][%d] priceTypeUserGroupsGetAllOK %s", 200, payload)
}

func (o *PriceTypeUserGroupsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypeUserGroups][%d] priceTypeUserGroupsGetAllOK %s", 200, payload)
}

func (o *PriceTypeUserGroupsGetAllOK) GetPayload() []*models.PriceTypeUserGroup {
	return o.Payload
}

func (o *PriceTypeUserGroupsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPriceTypeUserGroupsGetAllDefault creates a PriceTypeUserGroupsGetAllDefault with default headers values
func NewPriceTypeUserGroupsGetAllDefault(code int) *PriceTypeUserGroupsGetAllDefault {
	return &PriceTypeUserGroupsGetAllDefault{
		_statusCode: code,
	}
}

/*
PriceTypeUserGroupsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type PriceTypeUserGroupsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this price type user groups get all default response has a 2xx status code
func (o *PriceTypeUserGroupsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this price type user groups get all default response has a 3xx status code
func (o *PriceTypeUserGroupsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this price type user groups get all default response has a 4xx status code
func (o *PriceTypeUserGroupsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this price type user groups get all default response has a 5xx status code
func (o *PriceTypeUserGroupsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this price type user groups get all default response a status code equal to that given
func (o *PriceTypeUserGroupsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the price type user groups get all default response
func (o *PriceTypeUserGroupsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *PriceTypeUserGroupsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypeUserGroups][%d] PriceTypeUserGroups_GetAll default %s", o._statusCode, payload)
}

func (o *PriceTypeUserGroupsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PriceTypeUserGroups][%d] PriceTypeUserGroups_GetAll default %s", o._statusCode, payload)
}

func (o *PriceTypeUserGroupsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PriceTypeUserGroupsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
