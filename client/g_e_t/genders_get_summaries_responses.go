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

// GendersGetSummariesReader is a Reader for the GendersGetSummaries structure.
type GendersGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GendersGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGendersGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGendersGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGendersGetSummariesOK creates a GendersGetSummariesOK with default headers values
func NewGendersGetSummariesOK() *GendersGetSummariesOK {
	return &GendersGetSummariesOK{}
}

/*
GendersGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type GendersGetSummariesOK struct {
	Payload []*models.GenderSummary
}

// IsSuccess returns true when this genders get summaries o k response has a 2xx status code
func (o *GendersGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this genders get summaries o k response has a 3xx status code
func (o *GendersGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this genders get summaries o k response has a 4xx status code
func (o *GendersGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this genders get summaries o k response has a 5xx status code
func (o *GendersGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this genders get summaries o k response a status code equal to that given
func (o *GendersGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the genders get summaries o k response
func (o *GendersGetSummariesOK) Code() int {
	return 200
}

func (o *GendersGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Genders/Summary][%d] gendersGetSummariesOK %s", 200, payload)
}

func (o *GendersGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Genders/Summary][%d] gendersGetSummariesOK %s", 200, payload)
}

func (o *GendersGetSummariesOK) GetPayload() []*models.GenderSummary {
	return o.Payload
}

func (o *GendersGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGendersGetSummariesDefault creates a GendersGetSummariesDefault with default headers values
func NewGendersGetSummariesDefault(code int) *GendersGetSummariesDefault {
	return &GendersGetSummariesDefault{
		_statusCode: code,
	}
}

/*
GendersGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type GendersGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this genders get summaries default response has a 2xx status code
func (o *GendersGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this genders get summaries default response has a 3xx status code
func (o *GendersGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this genders get summaries default response has a 4xx status code
func (o *GendersGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this genders get summaries default response has a 5xx status code
func (o *GendersGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this genders get summaries default response a status code equal to that given
func (o *GendersGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the genders get summaries default response
func (o *GendersGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *GendersGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Genders/Summary][%d] Genders_GetSummaries default %s", o._statusCode, payload)
}

func (o *GendersGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Genders/Summary][%d] Genders_GetSummaries default %s", o._statusCode, payload)
}

func (o *GendersGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *GendersGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}