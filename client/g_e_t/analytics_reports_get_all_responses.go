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

// AnalyticsReportsGetAllReader is a Reader for the AnalyticsReportsGetAll structure.
type AnalyticsReportsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AnalyticsReportsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAnalyticsReportsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAnalyticsReportsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAnalyticsReportsGetAllOK creates a AnalyticsReportsGetAllOK with default headers values
func NewAnalyticsReportsGetAllOK() *AnalyticsReportsGetAllOK {
	return &AnalyticsReportsGetAllOK{}
}

/*
AnalyticsReportsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type AnalyticsReportsGetAllOK struct {
	Payload []*models.AnalyticsReport
}

// IsSuccess returns true when this analytics reports get all o k response has a 2xx status code
func (o *AnalyticsReportsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this analytics reports get all o k response has a 3xx status code
func (o *AnalyticsReportsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this analytics reports get all o k response has a 4xx status code
func (o *AnalyticsReportsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this analytics reports get all o k response has a 5xx status code
func (o *AnalyticsReportsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this analytics reports get all o k response a status code equal to that given
func (o *AnalyticsReportsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the analytics reports get all o k response
func (o *AnalyticsReportsGetAllOK) Code() int {
	return 200
}

func (o *AnalyticsReportsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Reporting/AnalyticsReports][%d] analyticsReportsGetAllOK %s", 200, payload)
}

func (o *AnalyticsReportsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Reporting/AnalyticsReports][%d] analyticsReportsGetAllOK %s", 200, payload)
}

func (o *AnalyticsReportsGetAllOK) GetPayload() []*models.AnalyticsReport {
	return o.Payload
}

func (o *AnalyticsReportsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAnalyticsReportsGetAllDefault creates a AnalyticsReportsGetAllDefault with default headers values
func NewAnalyticsReportsGetAllDefault(code int) *AnalyticsReportsGetAllDefault {
	return &AnalyticsReportsGetAllDefault{
		_statusCode: code,
	}
}

/*
AnalyticsReportsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type AnalyticsReportsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this analytics reports get all default response has a 2xx status code
func (o *AnalyticsReportsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this analytics reports get all default response has a 3xx status code
func (o *AnalyticsReportsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this analytics reports get all default response has a 4xx status code
func (o *AnalyticsReportsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this analytics reports get all default response has a 5xx status code
func (o *AnalyticsReportsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this analytics reports get all default response a status code equal to that given
func (o *AnalyticsReportsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the analytics reports get all default response
func (o *AnalyticsReportsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *AnalyticsReportsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Reporting/AnalyticsReports][%d] AnalyticsReports_GetAll default %s", o._statusCode, payload)
}

func (o *AnalyticsReportsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Reporting/AnalyticsReports][%d] AnalyticsReports_GetAll default %s", o._statusCode, payload)
}

func (o *AnalyticsReportsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AnalyticsReportsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
