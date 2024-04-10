// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// ReportUserGroupsGetAllReader is a Reader for the ReportUserGroupsGetAll structure.
type ReportUserGroupsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ReportUserGroupsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewReportUserGroupsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/ReportUserGroups] ReportUserGroups_GetAll", response, response.Code())
	}
}

// NewReportUserGroupsGetAllOK creates a ReportUserGroupsGetAllOK with default headers values
func NewReportUserGroupsGetAllOK() *ReportUserGroupsGetAllOK {
	return &ReportUserGroupsGetAllOK{}
}

/*
ReportUserGroupsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type ReportUserGroupsGetAllOK struct {
	Payload []*models.ReportUserGroup
}

// IsSuccess returns true when this report user groups get all o k response has a 2xx status code
func (o *ReportUserGroupsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this report user groups get all o k response has a 3xx status code
func (o *ReportUserGroupsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this report user groups get all o k response has a 4xx status code
func (o *ReportUserGroupsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this report user groups get all o k response has a 5xx status code
func (o *ReportUserGroupsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this report user groups get all o k response a status code equal to that given
func (o *ReportUserGroupsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the report user groups get all o k response
func (o *ReportUserGroupsGetAllOK) Code() int {
	return 200
}

func (o *ReportUserGroupsGetAllOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/ReportUserGroups][%d] reportUserGroupsGetAllOK  %+v", 200, o.Payload)
}

func (o *ReportUserGroupsGetAllOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/ReportUserGroups][%d] reportUserGroupsGetAllOK  %+v", 200, o.Payload)
}

func (o *ReportUserGroupsGetAllOK) GetPayload() []*models.ReportUserGroup {
	return o.Payload
}

func (o *ReportUserGroupsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}