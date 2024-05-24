// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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

// ListCategoriesDeleteReader is a Reader for the ListCategoriesDelete structure.
type ListCategoriesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListCategoriesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewListCategoriesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewListCategoriesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewListCategoriesDeleteNoContent creates a ListCategoriesDeleteNoContent with default headers values
func NewListCategoriesDeleteNoContent() *ListCategoriesDeleteNoContent {
	return &ListCategoriesDeleteNoContent{}
}

/*
ListCategoriesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ListCategoriesDeleteNoContent struct {
}

// IsSuccess returns true when this list categories delete no content response has a 2xx status code
func (o *ListCategoriesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list categories delete no content response has a 3xx status code
func (o *ListCategoriesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list categories delete no content response has a 4xx status code
func (o *ListCategoriesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this list categories delete no content response has a 5xx status code
func (o *ListCategoriesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this list categories delete no content response a status code equal to that given
func (o *ListCategoriesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the list categories delete no content response
func (o *ListCategoriesDeleteNoContent) Code() int {
	return 204
}

func (o *ListCategoriesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ListCategories/{id}][%d] listCategoriesDeleteNoContent", 204)
}

func (o *ListCategoriesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ListCategories/{id}][%d] listCategoriesDeleteNoContent", 204)
}

func (o *ListCategoriesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewListCategoriesDeleteDefault creates a ListCategoriesDeleteDefault with default headers values
func NewListCategoriesDeleteDefault(code int) *ListCategoriesDeleteDefault {
	return &ListCategoriesDeleteDefault{
		_statusCode: code,
	}
}

/*
ListCategoriesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type ListCategoriesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this list categories delete default response has a 2xx status code
func (o *ListCategoriesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this list categories delete default response has a 3xx status code
func (o *ListCategoriesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this list categories delete default response has a 4xx status code
func (o *ListCategoriesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this list categories delete default response has a 5xx status code
func (o *ListCategoriesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this list categories delete default response a status code equal to that given
func (o *ListCategoriesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the list categories delete default response
func (o *ListCategoriesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *ListCategoriesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ListCategories/{id}][%d] ListCategories_Delete default %s", o._statusCode, payload)
}

func (o *ListCategoriesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ListCategories/{id}][%d] ListCategories_Delete default %s", o._statusCode, payload)
}

func (o *ListCategoriesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ListCategoriesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
