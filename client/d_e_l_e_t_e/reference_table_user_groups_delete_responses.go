// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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

// ReferenceTableUserGroupsDeleteReader is a Reader for the ReferenceTableUserGroupsDelete structure.
type ReferenceTableUserGroupsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ReferenceTableUserGroupsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewReferenceTableUserGroupsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewReferenceTableUserGroupsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewReferenceTableUserGroupsDeleteNoContent creates a ReferenceTableUserGroupsDeleteNoContent with default headers values
func NewReferenceTableUserGroupsDeleteNoContent() *ReferenceTableUserGroupsDeleteNoContent {
	return &ReferenceTableUserGroupsDeleteNoContent{}
}

/*
ReferenceTableUserGroupsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ReferenceTableUserGroupsDeleteNoContent struct {
}

// IsSuccess returns true when this reference table user groups delete no content response has a 2xx status code
func (o *ReferenceTableUserGroupsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this reference table user groups delete no content response has a 3xx status code
func (o *ReferenceTableUserGroupsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reference table user groups delete no content response has a 4xx status code
func (o *ReferenceTableUserGroupsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this reference table user groups delete no content response has a 5xx status code
func (o *ReferenceTableUserGroupsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this reference table user groups delete no content response a status code equal to that given
func (o *ReferenceTableUserGroupsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the reference table user groups delete no content response
func (o *ReferenceTableUserGroupsDeleteNoContent) Code() int {
	return 204
}

func (o *ReferenceTableUserGroupsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ReferenceTableUserGroups/{id}][%d] referenceTableUserGroupsDeleteNoContent", 204)
}

func (o *ReferenceTableUserGroupsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ReferenceTableUserGroups/{id}][%d] referenceTableUserGroupsDeleteNoContent", 204)
}

func (o *ReferenceTableUserGroupsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewReferenceTableUserGroupsDeleteDefault creates a ReferenceTableUserGroupsDeleteDefault with default headers values
func NewReferenceTableUserGroupsDeleteDefault(code int) *ReferenceTableUserGroupsDeleteDefault {
	return &ReferenceTableUserGroupsDeleteDefault{
		_statusCode: code,
	}
}

/*
ReferenceTableUserGroupsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type ReferenceTableUserGroupsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this reference table user groups delete default response has a 2xx status code
func (o *ReferenceTableUserGroupsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this reference table user groups delete default response has a 3xx status code
func (o *ReferenceTableUserGroupsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this reference table user groups delete default response has a 4xx status code
func (o *ReferenceTableUserGroupsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this reference table user groups delete default response has a 5xx status code
func (o *ReferenceTableUserGroupsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this reference table user groups delete default response a status code equal to that given
func (o *ReferenceTableUserGroupsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the reference table user groups delete default response
func (o *ReferenceTableUserGroupsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *ReferenceTableUserGroupsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ReferenceTableUserGroups/{id}][%d] ReferenceTableUserGroups_Delete default %s", o._statusCode, payload)
}

func (o *ReferenceTableUserGroupsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ReferenceTableUserGroups/{id}][%d] ReferenceTableUserGroups_Delete default %s", o._statusCode, payload)
}

func (o *ReferenceTableUserGroupsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ReferenceTableUserGroupsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
