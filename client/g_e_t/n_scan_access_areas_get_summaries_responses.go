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

// NScanAccessAreasGetSummariesReader is a Reader for the NScanAccessAreasGetSummaries structure.
type NScanAccessAreasGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *NScanAccessAreasGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewNScanAccessAreasGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewNScanAccessAreasGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewNScanAccessAreasGetSummariesOK creates a NScanAccessAreasGetSummariesOK with default headers values
func NewNScanAccessAreasGetSummariesOK() *NScanAccessAreasGetSummariesOK {
	return &NScanAccessAreasGetSummariesOK{}
}

/*
NScanAccessAreasGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type NScanAccessAreasGetSummariesOK struct {
	Payload []*models.NScanAccessAreaSummary
}

// IsSuccess returns true when this n scan access areas get summaries o k response has a 2xx status code
func (o *NScanAccessAreasGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this n scan access areas get summaries o k response has a 3xx status code
func (o *NScanAccessAreasGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this n scan access areas get summaries o k response has a 4xx status code
func (o *NScanAccessAreasGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this n scan access areas get summaries o k response has a 5xx status code
func (o *NScanAccessAreasGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this n scan access areas get summaries o k response a status code equal to that given
func (o *NScanAccessAreasGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the n scan access areas get summaries o k response
func (o *NScanAccessAreasGetSummariesOK) Code() int {
	return 200
}

func (o *NScanAccessAreasGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/NScanAccessAreas/Summary][%d] nScanAccessAreasGetSummariesOK %s", 200, payload)
}

func (o *NScanAccessAreasGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/NScanAccessAreas/Summary][%d] nScanAccessAreasGetSummariesOK %s", 200, payload)
}

func (o *NScanAccessAreasGetSummariesOK) GetPayload() []*models.NScanAccessAreaSummary {
	return o.Payload
}

func (o *NScanAccessAreasGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewNScanAccessAreasGetSummariesDefault creates a NScanAccessAreasGetSummariesDefault with default headers values
func NewNScanAccessAreasGetSummariesDefault(code int) *NScanAccessAreasGetSummariesDefault {
	return &NScanAccessAreasGetSummariesDefault{
		_statusCode: code,
	}
}

/*
NScanAccessAreasGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type NScanAccessAreasGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this n scan access areas get summaries default response has a 2xx status code
func (o *NScanAccessAreasGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this n scan access areas get summaries default response has a 3xx status code
func (o *NScanAccessAreasGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this n scan access areas get summaries default response has a 4xx status code
func (o *NScanAccessAreasGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this n scan access areas get summaries default response has a 5xx status code
func (o *NScanAccessAreasGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this n scan access areas get summaries default response a status code equal to that given
func (o *NScanAccessAreasGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the n scan access areas get summaries default response
func (o *NScanAccessAreasGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *NScanAccessAreasGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/NScanAccessAreas/Summary][%d] NScanAccessAreas_GetSummaries default %s", o._statusCode, payload)
}

func (o *NScanAccessAreasGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/NScanAccessAreas/Summary][%d] NScanAccessAreas_GetSummaries default %s", o._statusCode, payload)
}

func (o *NScanAccessAreasGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *NScanAccessAreasGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}