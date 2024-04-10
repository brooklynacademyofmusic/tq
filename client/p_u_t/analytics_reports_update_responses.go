// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// AnalyticsReportsUpdateReader is a Reader for the AnalyticsReportsUpdate structure.
type AnalyticsReportsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AnalyticsReportsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAnalyticsReportsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[PUT /Reporting/AnalyticsReports/{analyticsReportId}] AnalyticsReports_Update", response, response.Code())
	}
}

// NewAnalyticsReportsUpdateOK creates a AnalyticsReportsUpdateOK with default headers values
func NewAnalyticsReportsUpdateOK() *AnalyticsReportsUpdateOK {
	return &AnalyticsReportsUpdateOK{}
}

/*
AnalyticsReportsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type AnalyticsReportsUpdateOK struct {
	Payload *models.AnalyticsReport
}

// IsSuccess returns true when this analytics reports update o k response has a 2xx status code
func (o *AnalyticsReportsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this analytics reports update o k response has a 3xx status code
func (o *AnalyticsReportsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this analytics reports update o k response has a 4xx status code
func (o *AnalyticsReportsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this analytics reports update o k response has a 5xx status code
func (o *AnalyticsReportsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this analytics reports update o k response a status code equal to that given
func (o *AnalyticsReportsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the analytics reports update o k response
func (o *AnalyticsReportsUpdateOK) Code() int {
	return 200
}

func (o *AnalyticsReportsUpdateOK) Error() string {
	return fmt.Sprintf("[PUT /Reporting/AnalyticsReports/{analyticsReportId}][%d] analyticsReportsUpdateOK  %+v", 200, o.Payload)
}

func (o *AnalyticsReportsUpdateOK) String() string {
	return fmt.Sprintf("[PUT /Reporting/AnalyticsReports/{analyticsReportId}][%d] analyticsReportsUpdateOK  %+v", 200, o.Payload)
}

func (o *AnalyticsReportsUpdateOK) GetPayload() *models.AnalyticsReport {
	return o.Payload
}

func (o *AnalyticsReportsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AnalyticsReport)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}