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

// HoldCodeUserGroupsCreateReader is a Reader for the HoldCodeUserGroupsCreate structure.
type HoldCodeUserGroupsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *HoldCodeUserGroupsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewHoldCodeUserGroupsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewHoldCodeUserGroupsCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewHoldCodeUserGroupsCreateOK creates a HoldCodeUserGroupsCreateOK with default headers values
func NewHoldCodeUserGroupsCreateOK() *HoldCodeUserGroupsCreateOK {
	return &HoldCodeUserGroupsCreateOK{}
}

/*
HoldCodeUserGroupsCreateOK describes a response with status code 200, with default header values.

OK
*/
type HoldCodeUserGroupsCreateOK struct {
	Payload *models.HoldCodeUserGroup
}

// IsSuccess returns true when this hold code user groups create o k response has a 2xx status code
func (o *HoldCodeUserGroupsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this hold code user groups create o k response has a 3xx status code
func (o *HoldCodeUserGroupsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this hold code user groups create o k response has a 4xx status code
func (o *HoldCodeUserGroupsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this hold code user groups create o k response has a 5xx status code
func (o *HoldCodeUserGroupsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this hold code user groups create o k response a status code equal to that given
func (o *HoldCodeUserGroupsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the hold code user groups create o k response
func (o *HoldCodeUserGroupsCreateOK) Code() int {
	return 200
}

func (o *HoldCodeUserGroupsCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/HoldCodeUserGroups][%d] holdCodeUserGroupsCreateOK %s", 200, payload)
}

func (o *HoldCodeUserGroupsCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/HoldCodeUserGroups][%d] holdCodeUserGroupsCreateOK %s", 200, payload)
}

func (o *HoldCodeUserGroupsCreateOK) GetPayload() *models.HoldCodeUserGroup {
	return o.Payload
}

func (o *HoldCodeUserGroupsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.HoldCodeUserGroup)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewHoldCodeUserGroupsCreateDefault creates a HoldCodeUserGroupsCreateDefault with default headers values
func NewHoldCodeUserGroupsCreateDefault(code int) *HoldCodeUserGroupsCreateDefault {
	return &HoldCodeUserGroupsCreateDefault{
		_statusCode: code,
	}
}

/*
HoldCodeUserGroupsCreateDefault describes a response with status code -1, with default header values.

Error
*/
type HoldCodeUserGroupsCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this hold code user groups create default response has a 2xx status code
func (o *HoldCodeUserGroupsCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this hold code user groups create default response has a 3xx status code
func (o *HoldCodeUserGroupsCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this hold code user groups create default response has a 4xx status code
func (o *HoldCodeUserGroupsCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this hold code user groups create default response has a 5xx status code
func (o *HoldCodeUserGroupsCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this hold code user groups create default response a status code equal to that given
func (o *HoldCodeUserGroupsCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the hold code user groups create default response
func (o *HoldCodeUserGroupsCreateDefault) Code() int {
	return o._statusCode
}

func (o *HoldCodeUserGroupsCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/HoldCodeUserGroups][%d] HoldCodeUserGroups_Create default %s", o._statusCode, payload)
}

func (o *HoldCodeUserGroupsCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/HoldCodeUserGroups][%d] HoldCodeUserGroups_Create default %s", o._statusCode, payload)
}

func (o *HoldCodeUserGroupsCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *HoldCodeUserGroupsCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
