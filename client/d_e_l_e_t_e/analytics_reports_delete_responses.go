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

// AnalyticsReportsDeleteReader is a Reader for the AnalyticsReportsDelete structure.
type AnalyticsReportsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AnalyticsReportsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewAnalyticsReportsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAnalyticsReportsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAnalyticsReportsDeleteNoContent creates a AnalyticsReportsDeleteNoContent with default headers values
func NewAnalyticsReportsDeleteNoContent() *AnalyticsReportsDeleteNoContent {
	return &AnalyticsReportsDeleteNoContent{}
}

/*
AnalyticsReportsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type AnalyticsReportsDeleteNoContent struct {
}

// IsSuccess returns true when this analytics reports delete no content response has a 2xx status code
func (o *AnalyticsReportsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this analytics reports delete no content response has a 3xx status code
func (o *AnalyticsReportsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this analytics reports delete no content response has a 4xx status code
func (o *AnalyticsReportsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this analytics reports delete no content response has a 5xx status code
func (o *AnalyticsReportsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this analytics reports delete no content response a status code equal to that given
func (o *AnalyticsReportsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the analytics reports delete no content response
func (o *AnalyticsReportsDeleteNoContent) Code() int {
	return 204
}

func (o *AnalyticsReportsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /Reporting/AnalyticsReports/{analyticsReportId}][%d] analyticsReportsDeleteNoContent", 204)
}

func (o *AnalyticsReportsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /Reporting/AnalyticsReports/{analyticsReportId}][%d] analyticsReportsDeleteNoContent", 204)
}

func (o *AnalyticsReportsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewAnalyticsReportsDeleteDefault creates a AnalyticsReportsDeleteDefault with default headers values
func NewAnalyticsReportsDeleteDefault(code int) *AnalyticsReportsDeleteDefault {
	return &AnalyticsReportsDeleteDefault{
		_statusCode: code,
	}
}

/*
AnalyticsReportsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type AnalyticsReportsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this analytics reports delete default response has a 2xx status code
func (o *AnalyticsReportsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this analytics reports delete default response has a 3xx status code
func (o *AnalyticsReportsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this analytics reports delete default response has a 4xx status code
func (o *AnalyticsReportsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this analytics reports delete default response has a 5xx status code
func (o *AnalyticsReportsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this analytics reports delete default response a status code equal to that given
func (o *AnalyticsReportsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the analytics reports delete default response
func (o *AnalyticsReportsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *AnalyticsReportsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Reporting/AnalyticsReports/{analyticsReportId}][%d] AnalyticsReports_Delete default %s", o._statusCode, payload)
}

func (o *AnalyticsReportsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Reporting/AnalyticsReports/{analyticsReportId}][%d] AnalyticsReports_Delete default %s", o._statusCode, payload)
}

func (o *AnalyticsReportsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AnalyticsReportsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
