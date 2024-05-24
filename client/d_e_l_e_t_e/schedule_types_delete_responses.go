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

// ScheduleTypesDeleteReader is a Reader for the ScheduleTypesDelete structure.
type ScheduleTypesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ScheduleTypesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewScheduleTypesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewScheduleTypesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewScheduleTypesDeleteNoContent creates a ScheduleTypesDeleteNoContent with default headers values
func NewScheduleTypesDeleteNoContent() *ScheduleTypesDeleteNoContent {
	return &ScheduleTypesDeleteNoContent{}
}

/*
ScheduleTypesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ScheduleTypesDeleteNoContent struct {
}

// IsSuccess returns true when this schedule types delete no content response has a 2xx status code
func (o *ScheduleTypesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this schedule types delete no content response has a 3xx status code
func (o *ScheduleTypesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this schedule types delete no content response has a 4xx status code
func (o *ScheduleTypesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this schedule types delete no content response has a 5xx status code
func (o *ScheduleTypesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this schedule types delete no content response a status code equal to that given
func (o *ScheduleTypesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the schedule types delete no content response
func (o *ScheduleTypesDeleteNoContent) Code() int {
	return 204
}

func (o *ScheduleTypesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ScheduleTypes/{id}][%d] scheduleTypesDeleteNoContent", 204)
}

func (o *ScheduleTypesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ScheduleTypes/{id}][%d] scheduleTypesDeleteNoContent", 204)
}

func (o *ScheduleTypesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewScheduleTypesDeleteDefault creates a ScheduleTypesDeleteDefault with default headers values
func NewScheduleTypesDeleteDefault(code int) *ScheduleTypesDeleteDefault {
	return &ScheduleTypesDeleteDefault{
		_statusCode: code,
	}
}

/*
ScheduleTypesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type ScheduleTypesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this schedule types delete default response has a 2xx status code
func (o *ScheduleTypesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this schedule types delete default response has a 3xx status code
func (o *ScheduleTypesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this schedule types delete default response has a 4xx status code
func (o *ScheduleTypesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this schedule types delete default response has a 5xx status code
func (o *ScheduleTypesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this schedule types delete default response a status code equal to that given
func (o *ScheduleTypesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the schedule types delete default response
func (o *ScheduleTypesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *ScheduleTypesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ScheduleTypes/{id}][%d] ScheduleTypes_Delete default %s", o._statusCode, payload)
}

func (o *ScheduleTypesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ScheduleTypes/{id}][%d] ScheduleTypes_Delete default %s", o._statusCode, payload)
}

func (o *ScheduleTypesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ScheduleTypesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
