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

// RelationshipCategoriesDeleteReader is a Reader for the RelationshipCategoriesDelete structure.
type RelationshipCategoriesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RelationshipCategoriesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewRelationshipCategoriesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewRelationshipCategoriesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewRelationshipCategoriesDeleteNoContent creates a RelationshipCategoriesDeleteNoContent with default headers values
func NewRelationshipCategoriesDeleteNoContent() *RelationshipCategoriesDeleteNoContent {
	return &RelationshipCategoriesDeleteNoContent{}
}

/*
RelationshipCategoriesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type RelationshipCategoriesDeleteNoContent struct {
}

// IsSuccess returns true when this relationship categories delete no content response has a 2xx status code
func (o *RelationshipCategoriesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this relationship categories delete no content response has a 3xx status code
func (o *RelationshipCategoriesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this relationship categories delete no content response has a 4xx status code
func (o *RelationshipCategoriesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this relationship categories delete no content response has a 5xx status code
func (o *RelationshipCategoriesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this relationship categories delete no content response a status code equal to that given
func (o *RelationshipCategoriesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the relationship categories delete no content response
func (o *RelationshipCategoriesDeleteNoContent) Code() int {
	return 204
}

func (o *RelationshipCategoriesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/RelationshipCategories/{id}][%d] relationshipCategoriesDeleteNoContent", 204)
}

func (o *RelationshipCategoriesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/RelationshipCategories/{id}][%d] relationshipCategoriesDeleteNoContent", 204)
}

func (o *RelationshipCategoriesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRelationshipCategoriesDeleteDefault creates a RelationshipCategoriesDeleteDefault with default headers values
func NewRelationshipCategoriesDeleteDefault(code int) *RelationshipCategoriesDeleteDefault {
	return &RelationshipCategoriesDeleteDefault{
		_statusCode: code,
	}
}

/*
RelationshipCategoriesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type RelationshipCategoriesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this relationship categories delete default response has a 2xx status code
func (o *RelationshipCategoriesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this relationship categories delete default response has a 3xx status code
func (o *RelationshipCategoriesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this relationship categories delete default response has a 4xx status code
func (o *RelationshipCategoriesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this relationship categories delete default response has a 5xx status code
func (o *RelationshipCategoriesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this relationship categories delete default response a status code equal to that given
func (o *RelationshipCategoriesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the relationship categories delete default response
func (o *RelationshipCategoriesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *RelationshipCategoriesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/RelationshipCategories/{id}][%d] RelationshipCategories_Delete default %s", o._statusCode, payload)
}

func (o *RelationshipCategoriesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/RelationshipCategories/{id}][%d] RelationshipCategories_Delete default %s", o._statusCode, payload)
}

func (o *RelationshipCategoriesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *RelationshipCategoriesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
