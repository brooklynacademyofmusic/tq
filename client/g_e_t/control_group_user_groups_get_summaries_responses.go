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

// ControlGroupUserGroupsGetSummariesReader is a Reader for the ControlGroupUserGroupsGetSummaries structure.
type ControlGroupUserGroupsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ControlGroupUserGroupsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewControlGroupUserGroupsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewControlGroupUserGroupsGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewControlGroupUserGroupsGetSummariesOK creates a ControlGroupUserGroupsGetSummariesOK with default headers values
func NewControlGroupUserGroupsGetSummariesOK() *ControlGroupUserGroupsGetSummariesOK {
	return &ControlGroupUserGroupsGetSummariesOK{}
}

/*
ControlGroupUserGroupsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type ControlGroupUserGroupsGetSummariesOK struct {
	Payload []*models.ControlGroupUserGroupSummary
}

// IsSuccess returns true when this control group user groups get summaries o k response has a 2xx status code
func (o *ControlGroupUserGroupsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this control group user groups get summaries o k response has a 3xx status code
func (o *ControlGroupUserGroupsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this control group user groups get summaries o k response has a 4xx status code
func (o *ControlGroupUserGroupsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this control group user groups get summaries o k response has a 5xx status code
func (o *ControlGroupUserGroupsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this control group user groups get summaries o k response a status code equal to that given
func (o *ControlGroupUserGroupsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the control group user groups get summaries o k response
func (o *ControlGroupUserGroupsGetSummariesOK) Code() int {
	return 200
}

func (o *ControlGroupUserGroupsGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ControlGroupUserGroups/Summary][%d] controlGroupUserGroupsGetSummariesOK %s", 200, payload)
}

func (o *ControlGroupUserGroupsGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ControlGroupUserGroups/Summary][%d] controlGroupUserGroupsGetSummariesOK %s", 200, payload)
}

func (o *ControlGroupUserGroupsGetSummariesOK) GetPayload() []*models.ControlGroupUserGroupSummary {
	return o.Payload
}

func (o *ControlGroupUserGroupsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewControlGroupUserGroupsGetSummariesDefault creates a ControlGroupUserGroupsGetSummariesDefault with default headers values
func NewControlGroupUserGroupsGetSummariesDefault(code int) *ControlGroupUserGroupsGetSummariesDefault {
	return &ControlGroupUserGroupsGetSummariesDefault{
		_statusCode: code,
	}
}

/*
ControlGroupUserGroupsGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type ControlGroupUserGroupsGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this control group user groups get summaries default response has a 2xx status code
func (o *ControlGroupUserGroupsGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this control group user groups get summaries default response has a 3xx status code
func (o *ControlGroupUserGroupsGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this control group user groups get summaries default response has a 4xx status code
func (o *ControlGroupUserGroupsGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this control group user groups get summaries default response has a 5xx status code
func (o *ControlGroupUserGroupsGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this control group user groups get summaries default response a status code equal to that given
func (o *ControlGroupUserGroupsGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the control group user groups get summaries default response
func (o *ControlGroupUserGroupsGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *ControlGroupUserGroupsGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ControlGroupUserGroups/Summary][%d] ControlGroupUserGroups_GetSummaries default %s", o._statusCode, payload)
}

func (o *ControlGroupUserGroupsGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ControlGroupUserGroups/Summary][%d] ControlGroupUserGroups_GetSummaries default %s", o._statusCode, payload)
}

func (o *ControlGroupUserGroupsGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ControlGroupUserGroupsGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
