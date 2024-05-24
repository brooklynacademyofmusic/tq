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

// AnalyticsReportsGetReader is a Reader for the AnalyticsReportsGet structure.
type AnalyticsReportsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AnalyticsReportsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAnalyticsReportsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAnalyticsReportsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAnalyticsReportsGetOK creates a AnalyticsReportsGetOK with default headers values
func NewAnalyticsReportsGetOK() *AnalyticsReportsGetOK {
	return &AnalyticsReportsGetOK{}
}

/*
AnalyticsReportsGetOK describes a response with status code 200, with default header values.

OK
*/
type AnalyticsReportsGetOK struct {
	Payload *models.AnalyticsReport
}

// IsSuccess returns true when this analytics reports get o k response has a 2xx status code
func (o *AnalyticsReportsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this analytics reports get o k response has a 3xx status code
func (o *AnalyticsReportsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this analytics reports get o k response has a 4xx status code
func (o *AnalyticsReportsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this analytics reports get o k response has a 5xx status code
func (o *AnalyticsReportsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this analytics reports get o k response a status code equal to that given
func (o *AnalyticsReportsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the analytics reports get o k response
func (o *AnalyticsReportsGetOK) Code() int {
	return 200
}

func (o *AnalyticsReportsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Reporting/AnalyticsReports/{analyticsReportId}][%d] analyticsReportsGetOK %s", 200, payload)
}

func (o *AnalyticsReportsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Reporting/AnalyticsReports/{analyticsReportId}][%d] analyticsReportsGetOK %s", 200, payload)
}

func (o *AnalyticsReportsGetOK) GetPayload() *models.AnalyticsReport {
	return o.Payload
}

func (o *AnalyticsReportsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AnalyticsReport)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAnalyticsReportsGetDefault creates a AnalyticsReportsGetDefault with default headers values
func NewAnalyticsReportsGetDefault(code int) *AnalyticsReportsGetDefault {
	return &AnalyticsReportsGetDefault{
		_statusCode: code,
	}
}

/*
AnalyticsReportsGetDefault describes a response with status code -1, with default header values.

Error
*/
type AnalyticsReportsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this analytics reports get default response has a 2xx status code
func (o *AnalyticsReportsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this analytics reports get default response has a 3xx status code
func (o *AnalyticsReportsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this analytics reports get default response has a 4xx status code
func (o *AnalyticsReportsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this analytics reports get default response has a 5xx status code
func (o *AnalyticsReportsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this analytics reports get default response a status code equal to that given
func (o *AnalyticsReportsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the analytics reports get default response
func (o *AnalyticsReportsGetDefault) Code() int {
	return o._statusCode
}

func (o *AnalyticsReportsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Reporting/AnalyticsReports/{analyticsReportId}][%d] AnalyticsReports_Get default %s", o._statusCode, payload)
}

func (o *AnalyticsReportsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Reporting/AnalyticsReports/{analyticsReportId}][%d] AnalyticsReports_Get default %s", o._statusCode, payload)
}

func (o *AnalyticsReportsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AnalyticsReportsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
