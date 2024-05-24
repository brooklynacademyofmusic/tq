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

// ControlGroupsCreateReader is a Reader for the ControlGroupsCreate structure.
type ControlGroupsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ControlGroupsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewControlGroupsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewControlGroupsCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewControlGroupsCreateOK creates a ControlGroupsCreateOK with default headers values
func NewControlGroupsCreateOK() *ControlGroupsCreateOK {
	return &ControlGroupsCreateOK{}
}

/*
ControlGroupsCreateOK describes a response with status code 200, with default header values.

OK
*/
type ControlGroupsCreateOK struct {
	Payload *models.ControlGroup
}

// IsSuccess returns true when this control groups create o k response has a 2xx status code
func (o *ControlGroupsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this control groups create o k response has a 3xx status code
func (o *ControlGroupsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this control groups create o k response has a 4xx status code
func (o *ControlGroupsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this control groups create o k response has a 5xx status code
func (o *ControlGroupsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this control groups create o k response a status code equal to that given
func (o *ControlGroupsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the control groups create o k response
func (o *ControlGroupsCreateOK) Code() int {
	return 200
}

func (o *ControlGroupsCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ControlGroups][%d] controlGroupsCreateOK %s", 200, payload)
}

func (o *ControlGroupsCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ControlGroups][%d] controlGroupsCreateOK %s", 200, payload)
}

func (o *ControlGroupsCreateOK) GetPayload() *models.ControlGroup {
	return o.Payload
}

func (o *ControlGroupsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ControlGroup)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewControlGroupsCreateDefault creates a ControlGroupsCreateDefault with default headers values
func NewControlGroupsCreateDefault(code int) *ControlGroupsCreateDefault {
	return &ControlGroupsCreateDefault{
		_statusCode: code,
	}
}

/*
ControlGroupsCreateDefault describes a response with status code -1, with default header values.

Error
*/
type ControlGroupsCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this control groups create default response has a 2xx status code
func (o *ControlGroupsCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this control groups create default response has a 3xx status code
func (o *ControlGroupsCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this control groups create default response has a 4xx status code
func (o *ControlGroupsCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this control groups create default response has a 5xx status code
func (o *ControlGroupsCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this control groups create default response a status code equal to that given
func (o *ControlGroupsCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the control groups create default response
func (o *ControlGroupsCreateDefault) Code() int {
	return o._statusCode
}

func (o *ControlGroupsCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ControlGroups][%d] ControlGroups_Create default %s", o._statusCode, payload)
}

func (o *ControlGroupsCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ControlGroups][%d] ControlGroups_Create default %s", o._statusCode, payload)
}

func (o *ControlGroupsCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ControlGroupsCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
