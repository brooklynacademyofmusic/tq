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

// ServiceResourceUserGroupsDeleteReader is a Reader for the ServiceResourceUserGroupsDelete structure.
type ServiceResourceUserGroupsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ServiceResourceUserGroupsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewServiceResourceUserGroupsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewServiceResourceUserGroupsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewServiceResourceUserGroupsDeleteNoContent creates a ServiceResourceUserGroupsDeleteNoContent with default headers values
func NewServiceResourceUserGroupsDeleteNoContent() *ServiceResourceUserGroupsDeleteNoContent {
	return &ServiceResourceUserGroupsDeleteNoContent{}
}

/*
ServiceResourceUserGroupsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ServiceResourceUserGroupsDeleteNoContent struct {
}

// IsSuccess returns true when this service resource user groups delete no content response has a 2xx status code
func (o *ServiceResourceUserGroupsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this service resource user groups delete no content response has a 3xx status code
func (o *ServiceResourceUserGroupsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this service resource user groups delete no content response has a 4xx status code
func (o *ServiceResourceUserGroupsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this service resource user groups delete no content response has a 5xx status code
func (o *ServiceResourceUserGroupsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this service resource user groups delete no content response a status code equal to that given
func (o *ServiceResourceUserGroupsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the service resource user groups delete no content response
func (o *ServiceResourceUserGroupsDeleteNoContent) Code() int {
	return 204
}

func (o *ServiceResourceUserGroupsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ServiceResourceUserGroups/{id}][%d] serviceResourceUserGroupsDeleteNoContent", 204)
}

func (o *ServiceResourceUserGroupsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ServiceResourceUserGroups/{id}][%d] serviceResourceUserGroupsDeleteNoContent", 204)
}

func (o *ServiceResourceUserGroupsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewServiceResourceUserGroupsDeleteDefault creates a ServiceResourceUserGroupsDeleteDefault with default headers values
func NewServiceResourceUserGroupsDeleteDefault(code int) *ServiceResourceUserGroupsDeleteDefault {
	return &ServiceResourceUserGroupsDeleteDefault{
		_statusCode: code,
	}
}

/*
ServiceResourceUserGroupsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type ServiceResourceUserGroupsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this service resource user groups delete default response has a 2xx status code
func (o *ServiceResourceUserGroupsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this service resource user groups delete default response has a 3xx status code
func (o *ServiceResourceUserGroupsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this service resource user groups delete default response has a 4xx status code
func (o *ServiceResourceUserGroupsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this service resource user groups delete default response has a 5xx status code
func (o *ServiceResourceUserGroupsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this service resource user groups delete default response a status code equal to that given
func (o *ServiceResourceUserGroupsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the service resource user groups delete default response
func (o *ServiceResourceUserGroupsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *ServiceResourceUserGroupsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ServiceResourceUserGroups/{id}][%d] ServiceResourceUserGroups_Delete default %s", o._statusCode, payload)
}

func (o *ServiceResourceUserGroupsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ServiceResourceUserGroups/{id}][%d] ServiceResourceUserGroups_Delete default %s", o._statusCode, payload)
}

func (o *ServiceResourceUserGroupsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ServiceResourceUserGroupsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
