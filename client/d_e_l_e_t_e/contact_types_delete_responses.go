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

// ContactTypesDeleteReader is a Reader for the ContactTypesDelete structure.
type ContactTypesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ContactTypesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewContactTypesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewContactTypesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewContactTypesDeleteNoContent creates a ContactTypesDeleteNoContent with default headers values
func NewContactTypesDeleteNoContent() *ContactTypesDeleteNoContent {
	return &ContactTypesDeleteNoContent{}
}

/*
ContactTypesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ContactTypesDeleteNoContent struct {
}

// IsSuccess returns true when this contact types delete no content response has a 2xx status code
func (o *ContactTypesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this contact types delete no content response has a 3xx status code
func (o *ContactTypesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this contact types delete no content response has a 4xx status code
func (o *ContactTypesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this contact types delete no content response has a 5xx status code
func (o *ContactTypesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this contact types delete no content response a status code equal to that given
func (o *ContactTypesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the contact types delete no content response
func (o *ContactTypesDeleteNoContent) Code() int {
	return 204
}

func (o *ContactTypesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ContactTypes/{id}][%d] contactTypesDeleteNoContent", 204)
}

func (o *ContactTypesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ContactTypes/{id}][%d] contactTypesDeleteNoContent", 204)
}

func (o *ContactTypesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewContactTypesDeleteDefault creates a ContactTypesDeleteDefault with default headers values
func NewContactTypesDeleteDefault(code int) *ContactTypesDeleteDefault {
	return &ContactTypesDeleteDefault{
		_statusCode: code,
	}
}

/*
ContactTypesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type ContactTypesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this contact types delete default response has a 2xx status code
func (o *ContactTypesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this contact types delete default response has a 3xx status code
func (o *ContactTypesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this contact types delete default response has a 4xx status code
func (o *ContactTypesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this contact types delete default response has a 5xx status code
func (o *ContactTypesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this contact types delete default response a status code equal to that given
func (o *ContactTypesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the contact types delete default response
func (o *ContactTypesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *ContactTypesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ContactTypes/{id}][%d] ContactTypes_Delete default %s", o._statusCode, payload)
}

func (o *ContactTypesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ContactTypes/{id}][%d] ContactTypes_Delete default %s", o._statusCode, payload)
}

func (o *ContactTypesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ContactTypesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
