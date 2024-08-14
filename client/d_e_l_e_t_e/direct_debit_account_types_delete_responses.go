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

// DirectDebitAccountTypesDeleteReader is a Reader for the DirectDebitAccountTypesDelete structure.
type DirectDebitAccountTypesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DirectDebitAccountTypesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDirectDebitAccountTypesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewDirectDebitAccountTypesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewDirectDebitAccountTypesDeleteNoContent creates a DirectDebitAccountTypesDeleteNoContent with default headers values
func NewDirectDebitAccountTypesDeleteNoContent() *DirectDebitAccountTypesDeleteNoContent {
	return &DirectDebitAccountTypesDeleteNoContent{}
}

/*
DirectDebitAccountTypesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type DirectDebitAccountTypesDeleteNoContent struct {
}

// IsSuccess returns true when this direct debit account types delete no content response has a 2xx status code
func (o *DirectDebitAccountTypesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this direct debit account types delete no content response has a 3xx status code
func (o *DirectDebitAccountTypesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this direct debit account types delete no content response has a 4xx status code
func (o *DirectDebitAccountTypesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this direct debit account types delete no content response has a 5xx status code
func (o *DirectDebitAccountTypesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this direct debit account types delete no content response a status code equal to that given
func (o *DirectDebitAccountTypesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the direct debit account types delete no content response
func (o *DirectDebitAccountTypesDeleteNoContent) Code() int {
	return 204
}

func (o *DirectDebitAccountTypesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/DirectDebitAccountTypes/{id}][%d] directDebitAccountTypesDeleteNoContent", 204)
}

func (o *DirectDebitAccountTypesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/DirectDebitAccountTypes/{id}][%d] directDebitAccountTypesDeleteNoContent", 204)
}

func (o *DirectDebitAccountTypesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDirectDebitAccountTypesDeleteDefault creates a DirectDebitAccountTypesDeleteDefault with default headers values
func NewDirectDebitAccountTypesDeleteDefault(code int) *DirectDebitAccountTypesDeleteDefault {
	return &DirectDebitAccountTypesDeleteDefault{
		_statusCode: code,
	}
}

/*
DirectDebitAccountTypesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type DirectDebitAccountTypesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this direct debit account types delete default response has a 2xx status code
func (o *DirectDebitAccountTypesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this direct debit account types delete default response has a 3xx status code
func (o *DirectDebitAccountTypesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this direct debit account types delete default response has a 4xx status code
func (o *DirectDebitAccountTypesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this direct debit account types delete default response has a 5xx status code
func (o *DirectDebitAccountTypesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this direct debit account types delete default response a status code equal to that given
func (o *DirectDebitAccountTypesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the direct debit account types delete default response
func (o *DirectDebitAccountTypesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *DirectDebitAccountTypesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/DirectDebitAccountTypes/{id}][%d] DirectDebitAccountTypes_Delete default %s", o._statusCode, payload)
}

func (o *DirectDebitAccountTypesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/DirectDebitAccountTypes/{id}][%d] DirectDebitAccountTypes_Delete default %s", o._statusCode, payload)
}

func (o *DirectDebitAccountTypesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *DirectDebitAccountTypesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}