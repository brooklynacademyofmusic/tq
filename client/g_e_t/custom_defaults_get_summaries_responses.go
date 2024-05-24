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

// CustomDefaultsGetSummariesReader is a Reader for the CustomDefaultsGetSummaries structure.
type CustomDefaultsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CustomDefaultsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCustomDefaultsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCustomDefaultsGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCustomDefaultsGetSummariesOK creates a CustomDefaultsGetSummariesOK with default headers values
func NewCustomDefaultsGetSummariesOK() *CustomDefaultsGetSummariesOK {
	return &CustomDefaultsGetSummariesOK{}
}

/*
CustomDefaultsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type CustomDefaultsGetSummariesOK struct {
	Payload []*models.CustomDefaultSummary
}

// IsSuccess returns true when this custom defaults get summaries o k response has a 2xx status code
func (o *CustomDefaultsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this custom defaults get summaries o k response has a 3xx status code
func (o *CustomDefaultsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this custom defaults get summaries o k response has a 4xx status code
func (o *CustomDefaultsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this custom defaults get summaries o k response has a 5xx status code
func (o *CustomDefaultsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this custom defaults get summaries o k response a status code equal to that given
func (o *CustomDefaultsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the custom defaults get summaries o k response
func (o *CustomDefaultsGetSummariesOK) Code() int {
	return 200
}

func (o *CustomDefaultsGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CustomDefaults/Summary][%d] customDefaultsGetSummariesOK %s", 200, payload)
}

func (o *CustomDefaultsGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CustomDefaults/Summary][%d] customDefaultsGetSummariesOK %s", 200, payload)
}

func (o *CustomDefaultsGetSummariesOK) GetPayload() []*models.CustomDefaultSummary {
	return o.Payload
}

func (o *CustomDefaultsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCustomDefaultsGetSummariesDefault creates a CustomDefaultsGetSummariesDefault with default headers values
func NewCustomDefaultsGetSummariesDefault(code int) *CustomDefaultsGetSummariesDefault {
	return &CustomDefaultsGetSummariesDefault{
		_statusCode: code,
	}
}

/*
CustomDefaultsGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type CustomDefaultsGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this custom defaults get summaries default response has a 2xx status code
func (o *CustomDefaultsGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this custom defaults get summaries default response has a 3xx status code
func (o *CustomDefaultsGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this custom defaults get summaries default response has a 4xx status code
func (o *CustomDefaultsGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this custom defaults get summaries default response has a 5xx status code
func (o *CustomDefaultsGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this custom defaults get summaries default response a status code equal to that given
func (o *CustomDefaultsGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the custom defaults get summaries default response
func (o *CustomDefaultsGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *CustomDefaultsGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CustomDefaults/Summary][%d] CustomDefaults_GetSummaries default %s", o._statusCode, payload)
}

func (o *CustomDefaultsGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CustomDefaults/Summary][%d] CustomDefaults_GetSummaries default %s", o._statusCode, payload)
}

func (o *CustomDefaultsGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CustomDefaultsGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
