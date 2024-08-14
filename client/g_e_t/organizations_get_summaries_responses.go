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

// OrganizationsGetSummariesReader is a Reader for the OrganizationsGetSummaries structure.
type OrganizationsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *OrganizationsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewOrganizationsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewOrganizationsGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewOrganizationsGetSummariesOK creates a OrganizationsGetSummariesOK with default headers values
func NewOrganizationsGetSummariesOK() *OrganizationsGetSummariesOK {
	return &OrganizationsGetSummariesOK{}
}

/*
OrganizationsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type OrganizationsGetSummariesOK struct {
	Payload []*models.OrganizationSummary
}

// IsSuccess returns true when this organizations get summaries o k response has a 2xx status code
func (o *OrganizationsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this organizations get summaries o k response has a 3xx status code
func (o *OrganizationsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this organizations get summaries o k response has a 4xx status code
func (o *OrganizationsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this organizations get summaries o k response has a 5xx status code
func (o *OrganizationsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this organizations get summaries o k response a status code equal to that given
func (o *OrganizationsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the organizations get summaries o k response
func (o *OrganizationsGetSummariesOK) Code() int {
	return 200
}

func (o *OrganizationsGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Organizations/Summary][%d] organizationsGetSummariesOK %s", 200, payload)
}

func (o *OrganizationsGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Organizations/Summary][%d] organizationsGetSummariesOK %s", 200, payload)
}

func (o *OrganizationsGetSummariesOK) GetPayload() []*models.OrganizationSummary {
	return o.Payload
}

func (o *OrganizationsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOrganizationsGetSummariesDefault creates a OrganizationsGetSummariesDefault with default headers values
func NewOrganizationsGetSummariesDefault(code int) *OrganizationsGetSummariesDefault {
	return &OrganizationsGetSummariesDefault{
		_statusCode: code,
	}
}

/*
OrganizationsGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type OrganizationsGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this organizations get summaries default response has a 2xx status code
func (o *OrganizationsGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this organizations get summaries default response has a 3xx status code
func (o *OrganizationsGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this organizations get summaries default response has a 4xx status code
func (o *OrganizationsGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this organizations get summaries default response has a 5xx status code
func (o *OrganizationsGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this organizations get summaries default response a status code equal to that given
func (o *OrganizationsGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the organizations get summaries default response
func (o *OrganizationsGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *OrganizationsGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Organizations/Summary][%d] Organizations_GetSummaries default %s", o._statusCode, payload)
}

func (o *OrganizationsGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Organizations/Summary][%d] Organizations_GetSummaries default %s", o._statusCode, payload)
}

func (o *OrganizationsGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *OrganizationsGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}