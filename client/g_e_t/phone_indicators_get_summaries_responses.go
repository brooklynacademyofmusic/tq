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

// PhoneIndicatorsGetSummariesReader is a Reader for the PhoneIndicatorsGetSummaries structure.
type PhoneIndicatorsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PhoneIndicatorsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPhoneIndicatorsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPhoneIndicatorsGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPhoneIndicatorsGetSummariesOK creates a PhoneIndicatorsGetSummariesOK with default headers values
func NewPhoneIndicatorsGetSummariesOK() *PhoneIndicatorsGetSummariesOK {
	return &PhoneIndicatorsGetSummariesOK{}
}

/*
PhoneIndicatorsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type PhoneIndicatorsGetSummariesOK struct {
	Payload []*models.PhoneIndicatorSummary
}

// IsSuccess returns true when this phone indicators get summaries o k response has a 2xx status code
func (o *PhoneIndicatorsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this phone indicators get summaries o k response has a 3xx status code
func (o *PhoneIndicatorsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this phone indicators get summaries o k response has a 4xx status code
func (o *PhoneIndicatorsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this phone indicators get summaries o k response has a 5xx status code
func (o *PhoneIndicatorsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this phone indicators get summaries o k response a status code equal to that given
func (o *PhoneIndicatorsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the phone indicators get summaries o k response
func (o *PhoneIndicatorsGetSummariesOK) Code() int {
	return 200
}

func (o *PhoneIndicatorsGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PhoneIndicators/Summary][%d] phoneIndicatorsGetSummariesOK %s", 200, payload)
}

func (o *PhoneIndicatorsGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PhoneIndicators/Summary][%d] phoneIndicatorsGetSummariesOK %s", 200, payload)
}

func (o *PhoneIndicatorsGetSummariesOK) GetPayload() []*models.PhoneIndicatorSummary {
	return o.Payload
}

func (o *PhoneIndicatorsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPhoneIndicatorsGetSummariesDefault creates a PhoneIndicatorsGetSummariesDefault with default headers values
func NewPhoneIndicatorsGetSummariesDefault(code int) *PhoneIndicatorsGetSummariesDefault {
	return &PhoneIndicatorsGetSummariesDefault{
		_statusCode: code,
	}
}

/*
PhoneIndicatorsGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type PhoneIndicatorsGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this phone indicators get summaries default response has a 2xx status code
func (o *PhoneIndicatorsGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this phone indicators get summaries default response has a 3xx status code
func (o *PhoneIndicatorsGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this phone indicators get summaries default response has a 4xx status code
func (o *PhoneIndicatorsGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this phone indicators get summaries default response has a 5xx status code
func (o *PhoneIndicatorsGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this phone indicators get summaries default response a status code equal to that given
func (o *PhoneIndicatorsGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the phone indicators get summaries default response
func (o *PhoneIndicatorsGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *PhoneIndicatorsGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PhoneIndicators/Summary][%d] PhoneIndicators_GetSummaries default %s", o._statusCode, payload)
}

func (o *PhoneIndicatorsGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PhoneIndicators/Summary][%d] PhoneIndicators_GetSummaries default %s", o._statusCode, payload)
}

func (o *PhoneIndicatorsGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PhoneIndicatorsGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
