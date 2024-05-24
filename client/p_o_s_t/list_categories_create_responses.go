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

// ListCategoriesCreateReader is a Reader for the ListCategoriesCreate structure.
type ListCategoriesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListCategoriesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListCategoriesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewListCategoriesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewListCategoriesCreateOK creates a ListCategoriesCreateOK with default headers values
func NewListCategoriesCreateOK() *ListCategoriesCreateOK {
	return &ListCategoriesCreateOK{}
}

/*
ListCategoriesCreateOK describes a response with status code 200, with default header values.

OK
*/
type ListCategoriesCreateOK struct {
	Payload *models.ListCategory
}

// IsSuccess returns true when this list categories create o k response has a 2xx status code
func (o *ListCategoriesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list categories create o k response has a 3xx status code
func (o *ListCategoriesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list categories create o k response has a 4xx status code
func (o *ListCategoriesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list categories create o k response has a 5xx status code
func (o *ListCategoriesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list categories create o k response a status code equal to that given
func (o *ListCategoriesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list categories create o k response
func (o *ListCategoriesCreateOK) Code() int {
	return 200
}

func (o *ListCategoriesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ListCategories][%d] listCategoriesCreateOK %s", 200, payload)
}

func (o *ListCategoriesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ListCategories][%d] listCategoriesCreateOK %s", 200, payload)
}

func (o *ListCategoriesCreateOK) GetPayload() *models.ListCategory {
	return o.Payload
}

func (o *ListCategoriesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ListCategory)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListCategoriesCreateDefault creates a ListCategoriesCreateDefault with default headers values
func NewListCategoriesCreateDefault(code int) *ListCategoriesCreateDefault {
	return &ListCategoriesCreateDefault{
		_statusCode: code,
	}
}

/*
ListCategoriesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type ListCategoriesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this list categories create default response has a 2xx status code
func (o *ListCategoriesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this list categories create default response has a 3xx status code
func (o *ListCategoriesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this list categories create default response has a 4xx status code
func (o *ListCategoriesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this list categories create default response has a 5xx status code
func (o *ListCategoriesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this list categories create default response a status code equal to that given
func (o *ListCategoriesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the list categories create default response
func (o *ListCategoriesCreateDefault) Code() int {
	return o._statusCode
}

func (o *ListCategoriesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ListCategories][%d] ListCategories_Create default %s", o._statusCode, payload)
}

func (o *ListCategoriesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ListCategories][%d] ListCategories_Create default %s", o._statusCode, payload)
}

func (o *ListCategoriesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ListCategoriesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
