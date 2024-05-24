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

// ContactPermissionCategoriesGetSummariesReader is a Reader for the ContactPermissionCategoriesGetSummaries structure.
type ContactPermissionCategoriesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ContactPermissionCategoriesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewContactPermissionCategoriesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewContactPermissionCategoriesGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewContactPermissionCategoriesGetSummariesOK creates a ContactPermissionCategoriesGetSummariesOK with default headers values
func NewContactPermissionCategoriesGetSummariesOK() *ContactPermissionCategoriesGetSummariesOK {
	return &ContactPermissionCategoriesGetSummariesOK{}
}

/*
ContactPermissionCategoriesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type ContactPermissionCategoriesGetSummariesOK struct {
	Payload []*models.ContactPermissionCategorySummary
}

// IsSuccess returns true when this contact permission categories get summaries o k response has a 2xx status code
func (o *ContactPermissionCategoriesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this contact permission categories get summaries o k response has a 3xx status code
func (o *ContactPermissionCategoriesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this contact permission categories get summaries o k response has a 4xx status code
func (o *ContactPermissionCategoriesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this contact permission categories get summaries o k response has a 5xx status code
func (o *ContactPermissionCategoriesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this contact permission categories get summaries o k response a status code equal to that given
func (o *ContactPermissionCategoriesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the contact permission categories get summaries o k response
func (o *ContactPermissionCategoriesGetSummariesOK) Code() int {
	return 200
}

func (o *ContactPermissionCategoriesGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ContactPermissionCategories/Summary][%d] contactPermissionCategoriesGetSummariesOK %s", 200, payload)
}

func (o *ContactPermissionCategoriesGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ContactPermissionCategories/Summary][%d] contactPermissionCategoriesGetSummariesOK %s", 200, payload)
}

func (o *ContactPermissionCategoriesGetSummariesOK) GetPayload() []*models.ContactPermissionCategorySummary {
	return o.Payload
}

func (o *ContactPermissionCategoriesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewContactPermissionCategoriesGetSummariesDefault creates a ContactPermissionCategoriesGetSummariesDefault with default headers values
func NewContactPermissionCategoriesGetSummariesDefault(code int) *ContactPermissionCategoriesGetSummariesDefault {
	return &ContactPermissionCategoriesGetSummariesDefault{
		_statusCode: code,
	}
}

/*
ContactPermissionCategoriesGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type ContactPermissionCategoriesGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this contact permission categories get summaries default response has a 2xx status code
func (o *ContactPermissionCategoriesGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this contact permission categories get summaries default response has a 3xx status code
func (o *ContactPermissionCategoriesGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this contact permission categories get summaries default response has a 4xx status code
func (o *ContactPermissionCategoriesGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this contact permission categories get summaries default response has a 5xx status code
func (o *ContactPermissionCategoriesGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this contact permission categories get summaries default response a status code equal to that given
func (o *ContactPermissionCategoriesGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the contact permission categories get summaries default response
func (o *ContactPermissionCategoriesGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *ContactPermissionCategoriesGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ContactPermissionCategories/Summary][%d] ContactPermissionCategories_GetSummaries default %s", o._statusCode, payload)
}

func (o *ContactPermissionCategoriesGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ContactPermissionCategories/Summary][%d] ContactPermissionCategories_GetSummaries default %s", o._statusCode, payload)
}

func (o *ContactPermissionCategoriesGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ContactPermissionCategoriesGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
