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

// HoldCodeUserGroupsGetAllReader is a Reader for the HoldCodeUserGroupsGetAll structure.
type HoldCodeUserGroupsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *HoldCodeUserGroupsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewHoldCodeUserGroupsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewHoldCodeUserGroupsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewHoldCodeUserGroupsGetAllOK creates a HoldCodeUserGroupsGetAllOK with default headers values
func NewHoldCodeUserGroupsGetAllOK() *HoldCodeUserGroupsGetAllOK {
	return &HoldCodeUserGroupsGetAllOK{}
}

/*
HoldCodeUserGroupsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type HoldCodeUserGroupsGetAllOK struct {
	Payload []*models.HoldCodeUserGroup
}

// IsSuccess returns true when this hold code user groups get all o k response has a 2xx status code
func (o *HoldCodeUserGroupsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this hold code user groups get all o k response has a 3xx status code
func (o *HoldCodeUserGroupsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this hold code user groups get all o k response has a 4xx status code
func (o *HoldCodeUserGroupsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this hold code user groups get all o k response has a 5xx status code
func (o *HoldCodeUserGroupsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this hold code user groups get all o k response a status code equal to that given
func (o *HoldCodeUserGroupsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the hold code user groups get all o k response
func (o *HoldCodeUserGroupsGetAllOK) Code() int {
	return 200
}

func (o *HoldCodeUserGroupsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/HoldCodeUserGroups][%d] holdCodeUserGroupsGetAllOK %s", 200, payload)
}

func (o *HoldCodeUserGroupsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/HoldCodeUserGroups][%d] holdCodeUserGroupsGetAllOK %s", 200, payload)
}

func (o *HoldCodeUserGroupsGetAllOK) GetPayload() []*models.HoldCodeUserGroup {
	return o.Payload
}

func (o *HoldCodeUserGroupsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewHoldCodeUserGroupsGetAllDefault creates a HoldCodeUserGroupsGetAllDefault with default headers values
func NewHoldCodeUserGroupsGetAllDefault(code int) *HoldCodeUserGroupsGetAllDefault {
	return &HoldCodeUserGroupsGetAllDefault{
		_statusCode: code,
	}
}

/*
HoldCodeUserGroupsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type HoldCodeUserGroupsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this hold code user groups get all default response has a 2xx status code
func (o *HoldCodeUserGroupsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this hold code user groups get all default response has a 3xx status code
func (o *HoldCodeUserGroupsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this hold code user groups get all default response has a 4xx status code
func (o *HoldCodeUserGroupsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this hold code user groups get all default response has a 5xx status code
func (o *HoldCodeUserGroupsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this hold code user groups get all default response a status code equal to that given
func (o *HoldCodeUserGroupsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the hold code user groups get all default response
func (o *HoldCodeUserGroupsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *HoldCodeUserGroupsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/HoldCodeUserGroups][%d] HoldCodeUserGroups_GetAll default %s", o._statusCode, payload)
}

func (o *HoldCodeUserGroupsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/HoldCodeUserGroups][%d] HoldCodeUserGroups_GetAll default %s", o._statusCode, payload)
}

func (o *HoldCodeUserGroupsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *HoldCodeUserGroupsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}