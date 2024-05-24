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

// ContactPointCategoriesGetReader is a Reader for the ContactPointCategoriesGet structure.
type ContactPointCategoriesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ContactPointCategoriesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewContactPointCategoriesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewContactPointCategoriesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewContactPointCategoriesGetOK creates a ContactPointCategoriesGetOK with default headers values
func NewContactPointCategoriesGetOK() *ContactPointCategoriesGetOK {
	return &ContactPointCategoriesGetOK{}
}

/*
ContactPointCategoriesGetOK describes a response with status code 200, with default header values.

OK
*/
type ContactPointCategoriesGetOK struct {
	Payload *models.ContactPointCategory
}

// IsSuccess returns true when this contact point categories get o k response has a 2xx status code
func (o *ContactPointCategoriesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this contact point categories get o k response has a 3xx status code
func (o *ContactPointCategoriesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this contact point categories get o k response has a 4xx status code
func (o *ContactPointCategoriesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this contact point categories get o k response has a 5xx status code
func (o *ContactPointCategoriesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this contact point categories get o k response a status code equal to that given
func (o *ContactPointCategoriesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the contact point categories get o k response
func (o *ContactPointCategoriesGetOK) Code() int {
	return 200
}

func (o *ContactPointCategoriesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ContactPointCategories/{id}][%d] contactPointCategoriesGetOK %s", 200, payload)
}

func (o *ContactPointCategoriesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ContactPointCategories/{id}][%d] contactPointCategoriesGetOK %s", 200, payload)
}

func (o *ContactPointCategoriesGetOK) GetPayload() *models.ContactPointCategory {
	return o.Payload
}

func (o *ContactPointCategoriesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ContactPointCategory)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewContactPointCategoriesGetDefault creates a ContactPointCategoriesGetDefault with default headers values
func NewContactPointCategoriesGetDefault(code int) *ContactPointCategoriesGetDefault {
	return &ContactPointCategoriesGetDefault{
		_statusCode: code,
	}
}

/*
ContactPointCategoriesGetDefault describes a response with status code -1, with default header values.

Error
*/
type ContactPointCategoriesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this contact point categories get default response has a 2xx status code
func (o *ContactPointCategoriesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this contact point categories get default response has a 3xx status code
func (o *ContactPointCategoriesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this contact point categories get default response has a 4xx status code
func (o *ContactPointCategoriesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this contact point categories get default response has a 5xx status code
func (o *ContactPointCategoriesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this contact point categories get default response a status code equal to that given
func (o *ContactPointCategoriesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the contact point categories get default response
func (o *ContactPointCategoriesGetDefault) Code() int {
	return o._statusCode
}

func (o *ContactPointCategoriesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ContactPointCategories/{id}][%d] ContactPointCategories_Get default %s", o._statusCode, payload)
}

func (o *ContactPointCategoriesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ContactPointCategories/{id}][%d] ContactPointCategories_Get default %s", o._statusCode, payload)
}

func (o *ContactPointCategoriesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ContactPointCategoriesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
