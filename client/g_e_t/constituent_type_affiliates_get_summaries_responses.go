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

// ConstituentTypeAffiliatesGetSummariesReader is a Reader for the ConstituentTypeAffiliatesGetSummaries structure.
type ConstituentTypeAffiliatesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ConstituentTypeAffiliatesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewConstituentTypeAffiliatesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewConstituentTypeAffiliatesGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewConstituentTypeAffiliatesGetSummariesOK creates a ConstituentTypeAffiliatesGetSummariesOK with default headers values
func NewConstituentTypeAffiliatesGetSummariesOK() *ConstituentTypeAffiliatesGetSummariesOK {
	return &ConstituentTypeAffiliatesGetSummariesOK{}
}

/*
ConstituentTypeAffiliatesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type ConstituentTypeAffiliatesGetSummariesOK struct {
	Payload []*models.ConstituentTypeAffiliateSummary
}

// IsSuccess returns true when this constituent type affiliates get summaries o k response has a 2xx status code
func (o *ConstituentTypeAffiliatesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this constituent type affiliates get summaries o k response has a 3xx status code
func (o *ConstituentTypeAffiliatesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this constituent type affiliates get summaries o k response has a 4xx status code
func (o *ConstituentTypeAffiliatesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this constituent type affiliates get summaries o k response has a 5xx status code
func (o *ConstituentTypeAffiliatesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this constituent type affiliates get summaries o k response a status code equal to that given
func (o *ConstituentTypeAffiliatesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the constituent type affiliates get summaries o k response
func (o *ConstituentTypeAffiliatesGetSummariesOK) Code() int {
	return 200
}

func (o *ConstituentTypeAffiliatesGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ConstituentTypeAffiliates/Summary][%d] constituentTypeAffiliatesGetSummariesOK %s", 200, payload)
}

func (o *ConstituentTypeAffiliatesGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ConstituentTypeAffiliates/Summary][%d] constituentTypeAffiliatesGetSummariesOK %s", 200, payload)
}

func (o *ConstituentTypeAffiliatesGetSummariesOK) GetPayload() []*models.ConstituentTypeAffiliateSummary {
	return o.Payload
}

func (o *ConstituentTypeAffiliatesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConstituentTypeAffiliatesGetSummariesDefault creates a ConstituentTypeAffiliatesGetSummariesDefault with default headers values
func NewConstituentTypeAffiliatesGetSummariesDefault(code int) *ConstituentTypeAffiliatesGetSummariesDefault {
	return &ConstituentTypeAffiliatesGetSummariesDefault{
		_statusCode: code,
	}
}

/*
ConstituentTypeAffiliatesGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type ConstituentTypeAffiliatesGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this constituent type affiliates get summaries default response has a 2xx status code
func (o *ConstituentTypeAffiliatesGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this constituent type affiliates get summaries default response has a 3xx status code
func (o *ConstituentTypeAffiliatesGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this constituent type affiliates get summaries default response has a 4xx status code
func (o *ConstituentTypeAffiliatesGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this constituent type affiliates get summaries default response has a 5xx status code
func (o *ConstituentTypeAffiliatesGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this constituent type affiliates get summaries default response a status code equal to that given
func (o *ConstituentTypeAffiliatesGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the constituent type affiliates get summaries default response
func (o *ConstituentTypeAffiliatesGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *ConstituentTypeAffiliatesGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ConstituentTypeAffiliates/Summary][%d] ConstituentTypeAffiliates_GetSummaries default %s", o._statusCode, payload)
}

func (o *ConstituentTypeAffiliatesGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ConstituentTypeAffiliates/Summary][%d] ConstituentTypeAffiliates_GetSummaries default %s", o._statusCode, payload)
}

func (o *ConstituentTypeAffiliatesGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ConstituentTypeAffiliatesGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
