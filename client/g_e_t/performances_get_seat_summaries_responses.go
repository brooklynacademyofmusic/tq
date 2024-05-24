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

// PerformancesGetSeatSummariesReader is a Reader for the PerformancesGetSeatSummaries structure.
type PerformancesGetSeatSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancesGetSeatSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPerformancesGetSeatSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformancesGetSeatSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformancesGetSeatSummariesOK creates a PerformancesGetSeatSummariesOK with default headers values
func NewPerformancesGetSeatSummariesOK() *PerformancesGetSeatSummariesOK {
	return &PerformancesGetSeatSummariesOK{}
}

/*
PerformancesGetSeatSummariesOK describes a response with status code 200, with default header values.

OK
*/
type PerformancesGetSeatSummariesOK struct {
	Payload []*models.SeatSummary
}

// IsSuccess returns true when this performances get seat summaries o k response has a 2xx status code
func (o *PerformancesGetSeatSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performances get seat summaries o k response has a 3xx status code
func (o *PerformancesGetSeatSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performances get seat summaries o k response has a 4xx status code
func (o *PerformancesGetSeatSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this performances get seat summaries o k response has a 5xx status code
func (o *PerformancesGetSeatSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this performances get seat summaries o k response a status code equal to that given
func (o *PerformancesGetSeatSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the performances get seat summaries o k response
func (o *PerformancesGetSeatSummariesOK) Code() int {
	return 200
}

func (o *PerformancesGetSeatSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/{performanceId}/Seats/Summary][%d] performancesGetSeatSummariesOK %s", 200, payload)
}

func (o *PerformancesGetSeatSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/{performanceId}/Seats/Summary][%d] performancesGetSeatSummariesOK %s", 200, payload)
}

func (o *PerformancesGetSeatSummariesOK) GetPayload() []*models.SeatSummary {
	return o.Payload
}

func (o *PerformancesGetSeatSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPerformancesGetSeatSummariesDefault creates a PerformancesGetSeatSummariesDefault with default headers values
func NewPerformancesGetSeatSummariesDefault(code int) *PerformancesGetSeatSummariesDefault {
	return &PerformancesGetSeatSummariesDefault{
		_statusCode: code,
	}
}

/*
PerformancesGetSeatSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type PerformancesGetSeatSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performances get seat summaries default response has a 2xx status code
func (o *PerformancesGetSeatSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performances get seat summaries default response has a 3xx status code
func (o *PerformancesGetSeatSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performances get seat summaries default response has a 4xx status code
func (o *PerformancesGetSeatSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performances get seat summaries default response has a 5xx status code
func (o *PerformancesGetSeatSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performances get seat summaries default response a status code equal to that given
func (o *PerformancesGetSeatSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performances get seat summaries default response
func (o *PerformancesGetSeatSummariesDefault) Code() int {
	return o._statusCode
}

func (o *PerformancesGetSeatSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/{performanceId}/Seats/Summary][%d] Performances_GetSeatSummaries default %s", o._statusCode, payload)
}

func (o *PerformancesGetSeatSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/{performanceId}/Seats/Summary][%d] Performances_GetSeatSummaries default %s", o._statusCode, payload)
}

func (o *PerformancesGetSeatSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformancesGetSeatSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
