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

// ControlGroupsGetSummariesReader is a Reader for the ControlGroupsGetSummaries structure.
type ControlGroupsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ControlGroupsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewControlGroupsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewControlGroupsGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewControlGroupsGetSummariesOK creates a ControlGroupsGetSummariesOK with default headers values
func NewControlGroupsGetSummariesOK() *ControlGroupsGetSummariesOK {
	return &ControlGroupsGetSummariesOK{}
}

/*
ControlGroupsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type ControlGroupsGetSummariesOK struct {
	Payload []*models.ControlGroupSummary
}

// IsSuccess returns true when this control groups get summaries o k response has a 2xx status code
func (o *ControlGroupsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this control groups get summaries o k response has a 3xx status code
func (o *ControlGroupsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this control groups get summaries o k response has a 4xx status code
func (o *ControlGroupsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this control groups get summaries o k response has a 5xx status code
func (o *ControlGroupsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this control groups get summaries o k response a status code equal to that given
func (o *ControlGroupsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the control groups get summaries o k response
func (o *ControlGroupsGetSummariesOK) Code() int {
	return 200
}

func (o *ControlGroupsGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ControlGroups/Summary][%d] controlGroupsGetSummariesOK %s", 200, payload)
}

func (o *ControlGroupsGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ControlGroups/Summary][%d] controlGroupsGetSummariesOK %s", 200, payload)
}

func (o *ControlGroupsGetSummariesOK) GetPayload() []*models.ControlGroupSummary {
	return o.Payload
}

func (o *ControlGroupsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewControlGroupsGetSummariesDefault creates a ControlGroupsGetSummariesDefault with default headers values
func NewControlGroupsGetSummariesDefault(code int) *ControlGroupsGetSummariesDefault {
	return &ControlGroupsGetSummariesDefault{
		_statusCode: code,
	}
}

/*
ControlGroupsGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type ControlGroupsGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this control groups get summaries default response has a 2xx status code
func (o *ControlGroupsGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this control groups get summaries default response has a 3xx status code
func (o *ControlGroupsGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this control groups get summaries default response has a 4xx status code
func (o *ControlGroupsGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this control groups get summaries default response has a 5xx status code
func (o *ControlGroupsGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this control groups get summaries default response a status code equal to that given
func (o *ControlGroupsGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the control groups get summaries default response
func (o *ControlGroupsGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *ControlGroupsGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ControlGroups/Summary][%d] ControlGroups_GetSummaries default %s", o._statusCode, payload)
}

func (o *ControlGroupsGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ControlGroups/Summary][%d] ControlGroups_GetSummaries default %s", o._statusCode, payload)
}

func (o *ControlGroupsGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ControlGroupsGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
