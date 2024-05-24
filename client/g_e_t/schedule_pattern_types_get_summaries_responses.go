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

// SchedulePatternTypesGetSummariesReader is a Reader for the SchedulePatternTypesGetSummaries structure.
type SchedulePatternTypesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SchedulePatternTypesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSchedulePatternTypesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSchedulePatternTypesGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSchedulePatternTypesGetSummariesOK creates a SchedulePatternTypesGetSummariesOK with default headers values
func NewSchedulePatternTypesGetSummariesOK() *SchedulePatternTypesGetSummariesOK {
	return &SchedulePatternTypesGetSummariesOK{}
}

/*
SchedulePatternTypesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type SchedulePatternTypesGetSummariesOK struct {
	Payload []*models.SchedulePatternTypeSummary
}

// IsSuccess returns true when this schedule pattern types get summaries o k response has a 2xx status code
func (o *SchedulePatternTypesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this schedule pattern types get summaries o k response has a 3xx status code
func (o *SchedulePatternTypesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this schedule pattern types get summaries o k response has a 4xx status code
func (o *SchedulePatternTypesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this schedule pattern types get summaries o k response has a 5xx status code
func (o *SchedulePatternTypesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this schedule pattern types get summaries o k response a status code equal to that given
func (o *SchedulePatternTypesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the schedule pattern types get summaries o k response
func (o *SchedulePatternTypesGetSummariesOK) Code() int {
	return 200
}

func (o *SchedulePatternTypesGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SchedulePatternTypes/Summary][%d] schedulePatternTypesGetSummariesOK %s", 200, payload)
}

func (o *SchedulePatternTypesGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SchedulePatternTypes/Summary][%d] schedulePatternTypesGetSummariesOK %s", 200, payload)
}

func (o *SchedulePatternTypesGetSummariesOK) GetPayload() []*models.SchedulePatternTypeSummary {
	return o.Payload
}

func (o *SchedulePatternTypesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSchedulePatternTypesGetSummariesDefault creates a SchedulePatternTypesGetSummariesDefault with default headers values
func NewSchedulePatternTypesGetSummariesDefault(code int) *SchedulePatternTypesGetSummariesDefault {
	return &SchedulePatternTypesGetSummariesDefault{
		_statusCode: code,
	}
}

/*
SchedulePatternTypesGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type SchedulePatternTypesGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this schedule pattern types get summaries default response has a 2xx status code
func (o *SchedulePatternTypesGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this schedule pattern types get summaries default response has a 3xx status code
func (o *SchedulePatternTypesGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this schedule pattern types get summaries default response has a 4xx status code
func (o *SchedulePatternTypesGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this schedule pattern types get summaries default response has a 5xx status code
func (o *SchedulePatternTypesGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this schedule pattern types get summaries default response a status code equal to that given
func (o *SchedulePatternTypesGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the schedule pattern types get summaries default response
func (o *SchedulePatternTypesGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *SchedulePatternTypesGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SchedulePatternTypes/Summary][%d] SchedulePatternTypes_GetSummaries default %s", o._statusCode, payload)
}

func (o *SchedulePatternTypesGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SchedulePatternTypes/Summary][%d] SchedulePatternTypes_GetSummaries default %s", o._statusCode, payload)
}

func (o *SchedulePatternTypesGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SchedulePatternTypesGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
