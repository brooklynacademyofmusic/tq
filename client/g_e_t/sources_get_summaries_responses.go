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

// SourcesGetSummariesReader is a Reader for the SourcesGetSummaries structure.
type SourcesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SourcesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSourcesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSourcesGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSourcesGetSummariesOK creates a SourcesGetSummariesOK with default headers values
func NewSourcesGetSummariesOK() *SourcesGetSummariesOK {
	return &SourcesGetSummariesOK{}
}

/*
SourcesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type SourcesGetSummariesOK struct {
	Payload []*models.SourceSummary
}

// IsSuccess returns true when this sources get summaries o k response has a 2xx status code
func (o *SourcesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this sources get summaries o k response has a 3xx status code
func (o *SourcesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this sources get summaries o k response has a 4xx status code
func (o *SourcesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this sources get summaries o k response has a 5xx status code
func (o *SourcesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this sources get summaries o k response a status code equal to that given
func (o *SourcesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the sources get summaries o k response
func (o *SourcesGetSummariesOK) Code() int {
	return 200
}

func (o *SourcesGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Sources/Summary][%d] sourcesGetSummariesOK %s", 200, payload)
}

func (o *SourcesGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Sources/Summary][%d] sourcesGetSummariesOK %s", 200, payload)
}

func (o *SourcesGetSummariesOK) GetPayload() []*models.SourceSummary {
	return o.Payload
}

func (o *SourcesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSourcesGetSummariesDefault creates a SourcesGetSummariesDefault with default headers values
func NewSourcesGetSummariesDefault(code int) *SourcesGetSummariesDefault {
	return &SourcesGetSummariesDefault{
		_statusCode: code,
	}
}

/*
SourcesGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type SourcesGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this sources get summaries default response has a 2xx status code
func (o *SourcesGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this sources get summaries default response has a 3xx status code
func (o *SourcesGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this sources get summaries default response has a 4xx status code
func (o *SourcesGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this sources get summaries default response has a 5xx status code
func (o *SourcesGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this sources get summaries default response a status code equal to that given
func (o *SourcesGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the sources get summaries default response
func (o *SourcesGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *SourcesGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Sources/Summary][%d] Sources_GetSummaries default %s", o._statusCode, payload)
}

func (o *SourcesGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Sources/Summary][%d] Sources_GetSummaries default %s", o._statusCode, payload)
}

func (o *SourcesGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SourcesGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}