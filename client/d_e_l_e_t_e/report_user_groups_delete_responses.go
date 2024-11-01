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

// ReportUserGroupsDeleteReader is a Reader for the ReportUserGroupsDelete structure.
type ReportUserGroupsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ReportUserGroupsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewReportUserGroupsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewReportUserGroupsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewReportUserGroupsDeleteNoContent creates a ReportUserGroupsDeleteNoContent with default headers values
func NewReportUserGroupsDeleteNoContent() *ReportUserGroupsDeleteNoContent {
	return &ReportUserGroupsDeleteNoContent{}
}

/*
ReportUserGroupsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ReportUserGroupsDeleteNoContent struct {
}

// IsSuccess returns true when this report user groups delete no content response has a 2xx status code
func (o *ReportUserGroupsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this report user groups delete no content response has a 3xx status code
func (o *ReportUserGroupsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this report user groups delete no content response has a 4xx status code
func (o *ReportUserGroupsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this report user groups delete no content response has a 5xx status code
func (o *ReportUserGroupsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this report user groups delete no content response a status code equal to that given
func (o *ReportUserGroupsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the report user groups delete no content response
func (o *ReportUserGroupsDeleteNoContent) Code() int {
	return 204
}

func (o *ReportUserGroupsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ReportUserGroups/{id}][%d] reportUserGroupsDeleteNoContent", 204)
}

func (o *ReportUserGroupsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ReportUserGroups/{id}][%d] reportUserGroupsDeleteNoContent", 204)
}

func (o *ReportUserGroupsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewReportUserGroupsDeleteDefault creates a ReportUserGroupsDeleteDefault with default headers values
func NewReportUserGroupsDeleteDefault(code int) *ReportUserGroupsDeleteDefault {
	return &ReportUserGroupsDeleteDefault{
		_statusCode: code,
	}
}

/*
ReportUserGroupsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type ReportUserGroupsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this report user groups delete default response has a 2xx status code
func (o *ReportUserGroupsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this report user groups delete default response has a 3xx status code
func (o *ReportUserGroupsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this report user groups delete default response has a 4xx status code
func (o *ReportUserGroupsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this report user groups delete default response has a 5xx status code
func (o *ReportUserGroupsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this report user groups delete default response a status code equal to that given
func (o *ReportUserGroupsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the report user groups delete default response
func (o *ReportUserGroupsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *ReportUserGroupsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ReportUserGroups/{id}][%d] ReportUserGroups_Delete default %s", o._statusCode, payload)
}

func (o *ReportUserGroupsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ReportUserGroups/{id}][%d] ReportUserGroups_Delete default %s", o._statusCode, payload)
}

func (o *ReportUserGroupsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ReportUserGroupsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}