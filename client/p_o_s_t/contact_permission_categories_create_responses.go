// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

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

// ContactPermissionCategoriesCreateReader is a Reader for the ContactPermissionCategoriesCreate structure.
type ContactPermissionCategoriesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ContactPermissionCategoriesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewContactPermissionCategoriesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewContactPermissionCategoriesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewContactPermissionCategoriesCreateOK creates a ContactPermissionCategoriesCreateOK with default headers values
func NewContactPermissionCategoriesCreateOK() *ContactPermissionCategoriesCreateOK {
	return &ContactPermissionCategoriesCreateOK{}
}

/*
ContactPermissionCategoriesCreateOK describes a response with status code 200, with default header values.

OK
*/
type ContactPermissionCategoriesCreateOK struct {
	Payload *models.ContactPermissionCategory
}

// IsSuccess returns true when this contact permission categories create o k response has a 2xx status code
func (o *ContactPermissionCategoriesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this contact permission categories create o k response has a 3xx status code
func (o *ContactPermissionCategoriesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this contact permission categories create o k response has a 4xx status code
func (o *ContactPermissionCategoriesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this contact permission categories create o k response has a 5xx status code
func (o *ContactPermissionCategoriesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this contact permission categories create o k response a status code equal to that given
func (o *ContactPermissionCategoriesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the contact permission categories create o k response
func (o *ContactPermissionCategoriesCreateOK) Code() int {
	return 200
}

func (o *ContactPermissionCategoriesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ContactPermissionCategories][%d] contactPermissionCategoriesCreateOK %s", 200, payload)
}

func (o *ContactPermissionCategoriesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ContactPermissionCategories][%d] contactPermissionCategoriesCreateOK %s", 200, payload)
}

func (o *ContactPermissionCategoriesCreateOK) GetPayload() *models.ContactPermissionCategory {
	return o.Payload
}

func (o *ContactPermissionCategoriesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ContactPermissionCategory)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewContactPermissionCategoriesCreateDefault creates a ContactPermissionCategoriesCreateDefault with default headers values
func NewContactPermissionCategoriesCreateDefault(code int) *ContactPermissionCategoriesCreateDefault {
	return &ContactPermissionCategoriesCreateDefault{
		_statusCode: code,
	}
}

/*
ContactPermissionCategoriesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type ContactPermissionCategoriesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this contact permission categories create default response has a 2xx status code
func (o *ContactPermissionCategoriesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this contact permission categories create default response has a 3xx status code
func (o *ContactPermissionCategoriesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this contact permission categories create default response has a 4xx status code
func (o *ContactPermissionCategoriesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this contact permission categories create default response has a 5xx status code
func (o *ContactPermissionCategoriesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this contact permission categories create default response a status code equal to that given
func (o *ContactPermissionCategoriesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the contact permission categories create default response
func (o *ContactPermissionCategoriesCreateDefault) Code() int {
	return o._statusCode
}

func (o *ContactPermissionCategoriesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ContactPermissionCategories][%d] ContactPermissionCategories_Create default %s", o._statusCode, payload)
}

func (o *ContactPermissionCategoriesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ContactPermissionCategories][%d] ContactPermissionCategories_Create default %s", o._statusCode, payload)
}

func (o *ContactPermissionCategoriesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ContactPermissionCategoriesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}