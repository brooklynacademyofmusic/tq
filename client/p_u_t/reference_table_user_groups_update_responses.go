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

// ReferenceTableUserGroupsUpdateReader is a Reader for the ReferenceTableUserGroupsUpdate structure.
type ReferenceTableUserGroupsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ReferenceTableUserGroupsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewReferenceTableUserGroupsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewReferenceTableUserGroupsUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewReferenceTableUserGroupsUpdateOK creates a ReferenceTableUserGroupsUpdateOK with default headers values
func NewReferenceTableUserGroupsUpdateOK() *ReferenceTableUserGroupsUpdateOK {
	return &ReferenceTableUserGroupsUpdateOK{}
}

/*
ReferenceTableUserGroupsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type ReferenceTableUserGroupsUpdateOK struct {
	Payload *models.ReferenceTableUserGroup
}

// IsSuccess returns true when this reference table user groups update o k response has a 2xx status code
func (o *ReferenceTableUserGroupsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this reference table user groups update o k response has a 3xx status code
func (o *ReferenceTableUserGroupsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reference table user groups update o k response has a 4xx status code
func (o *ReferenceTableUserGroupsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this reference table user groups update o k response has a 5xx status code
func (o *ReferenceTableUserGroupsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this reference table user groups update o k response a status code equal to that given
func (o *ReferenceTableUserGroupsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the reference table user groups update o k response
func (o *ReferenceTableUserGroupsUpdateOK) Code() int {
	return 200
}

func (o *ReferenceTableUserGroupsUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ReferenceTableUserGroups/{id}][%d] referenceTableUserGroupsUpdateOK %s", 200, payload)
}

func (o *ReferenceTableUserGroupsUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ReferenceTableUserGroups/{id}][%d] referenceTableUserGroupsUpdateOK %s", 200, payload)
}

func (o *ReferenceTableUserGroupsUpdateOK) GetPayload() *models.ReferenceTableUserGroup {
	return o.Payload
}

func (o *ReferenceTableUserGroupsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ReferenceTableUserGroup)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewReferenceTableUserGroupsUpdateDefault creates a ReferenceTableUserGroupsUpdateDefault with default headers values
func NewReferenceTableUserGroupsUpdateDefault(code int) *ReferenceTableUserGroupsUpdateDefault {
	return &ReferenceTableUserGroupsUpdateDefault{
		_statusCode: code,
	}
}

/*
ReferenceTableUserGroupsUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type ReferenceTableUserGroupsUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this reference table user groups update default response has a 2xx status code
func (o *ReferenceTableUserGroupsUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this reference table user groups update default response has a 3xx status code
func (o *ReferenceTableUserGroupsUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this reference table user groups update default response has a 4xx status code
func (o *ReferenceTableUserGroupsUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this reference table user groups update default response has a 5xx status code
func (o *ReferenceTableUserGroupsUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this reference table user groups update default response a status code equal to that given
func (o *ReferenceTableUserGroupsUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the reference table user groups update default response
func (o *ReferenceTableUserGroupsUpdateDefault) Code() int {
	return o._statusCode
}

func (o *ReferenceTableUserGroupsUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ReferenceTableUserGroups/{id}][%d] ReferenceTableUserGroups_Update default %s", o._statusCode, payload)
}

func (o *ReferenceTableUserGroupsUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ReferenceTableUserGroups/{id}][%d] ReferenceTableUserGroups_Update default %s", o._statusCode, payload)
}

func (o *ReferenceTableUserGroupsUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ReferenceTableUserGroupsUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
