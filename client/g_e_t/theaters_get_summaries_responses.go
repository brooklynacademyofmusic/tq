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

// TheatersGetSummariesReader is a Reader for the TheatersGetSummaries structure.
type TheatersGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TheatersGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTheatersGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewTheatersGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewTheatersGetSummariesOK creates a TheatersGetSummariesOK with default headers values
func NewTheatersGetSummariesOK() *TheatersGetSummariesOK {
	return &TheatersGetSummariesOK{}
}

/*
TheatersGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type TheatersGetSummariesOK struct {
	Payload []*models.TheaterSummary
}

// IsSuccess returns true when this theaters get summaries o k response has a 2xx status code
func (o *TheatersGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this theaters get summaries o k response has a 3xx status code
func (o *TheatersGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this theaters get summaries o k response has a 4xx status code
func (o *TheatersGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this theaters get summaries o k response has a 5xx status code
func (o *TheatersGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this theaters get summaries o k response a status code equal to that given
func (o *TheatersGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the theaters get summaries o k response
func (o *TheatersGetSummariesOK) Code() int {
	return 200
}

func (o *TheatersGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Theaters/Summary][%d] theatersGetSummariesOK %s", 200, payload)
}

func (o *TheatersGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Theaters/Summary][%d] theatersGetSummariesOK %s", 200, payload)
}

func (o *TheatersGetSummariesOK) GetPayload() []*models.TheaterSummary {
	return o.Payload
}

func (o *TheatersGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTheatersGetSummariesDefault creates a TheatersGetSummariesDefault with default headers values
func NewTheatersGetSummariesDefault(code int) *TheatersGetSummariesDefault {
	return &TheatersGetSummariesDefault{
		_statusCode: code,
	}
}

/*
TheatersGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type TheatersGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this theaters get summaries default response has a 2xx status code
func (o *TheatersGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this theaters get summaries default response has a 3xx status code
func (o *TheatersGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this theaters get summaries default response has a 4xx status code
func (o *TheatersGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this theaters get summaries default response has a 5xx status code
func (o *TheatersGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this theaters get summaries default response a status code equal to that given
func (o *TheatersGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the theaters get summaries default response
func (o *TheatersGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *TheatersGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Theaters/Summary][%d] Theaters_GetSummaries default %s", o._statusCode, payload)
}

func (o *TheatersGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Theaters/Summary][%d] Theaters_GetSummaries default %s", o._statusCode, payload)
}

func (o *TheatersGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *TheatersGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
