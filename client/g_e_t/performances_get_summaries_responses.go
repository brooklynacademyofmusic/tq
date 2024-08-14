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

// PerformancesGetSummariesReader is a Reader for the PerformancesGetSummaries structure.
type PerformancesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPerformancesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformancesGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformancesGetSummariesOK creates a PerformancesGetSummariesOK with default headers values
func NewPerformancesGetSummariesOK() *PerformancesGetSummariesOK {
	return &PerformancesGetSummariesOK{}
}

/*
PerformancesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type PerformancesGetSummariesOK struct {
	Payload []*models.PerformanceSummary
}

// IsSuccess returns true when this performances get summaries o k response has a 2xx status code
func (o *PerformancesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performances get summaries o k response has a 3xx status code
func (o *PerformancesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performances get summaries o k response has a 4xx status code
func (o *PerformancesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this performances get summaries o k response has a 5xx status code
func (o *PerformancesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this performances get summaries o k response a status code equal to that given
func (o *PerformancesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the performances get summaries o k response
func (o *PerformancesGetSummariesOK) Code() int {
	return 200
}

func (o *PerformancesGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/Summary][%d] performancesGetSummariesOK %s", 200, payload)
}

func (o *PerformancesGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/Summary][%d] performancesGetSummariesOK %s", 200, payload)
}

func (o *PerformancesGetSummariesOK) GetPayload() []*models.PerformanceSummary {
	return o.Payload
}

func (o *PerformancesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPerformancesGetSummariesDefault creates a PerformancesGetSummariesDefault with default headers values
func NewPerformancesGetSummariesDefault(code int) *PerformancesGetSummariesDefault {
	return &PerformancesGetSummariesDefault{
		_statusCode: code,
	}
}

/*
PerformancesGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type PerformancesGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performances get summaries default response has a 2xx status code
func (o *PerformancesGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performances get summaries default response has a 3xx status code
func (o *PerformancesGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performances get summaries default response has a 4xx status code
func (o *PerformancesGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performances get summaries default response has a 5xx status code
func (o *PerformancesGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performances get summaries default response a status code equal to that given
func (o *PerformancesGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performances get summaries default response
func (o *PerformancesGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *PerformancesGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/Summary][%d] Performances_GetSummaries default %s", o._statusCode, payload)
}

func (o *PerformancesGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/Summary][%d] Performances_GetSummaries default %s", o._statusCode, payload)
}

func (o *PerformancesGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformancesGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}