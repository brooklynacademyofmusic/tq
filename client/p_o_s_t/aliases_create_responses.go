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

// AliasesCreateReader is a Reader for the AliasesCreate structure.
type AliasesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AliasesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAliasesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAliasesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAliasesCreateOK creates a AliasesCreateOK with default headers values
func NewAliasesCreateOK() *AliasesCreateOK {
	return &AliasesCreateOK{}
}

/*
AliasesCreateOK describes a response with status code 200, with default header values.

OK
*/
type AliasesCreateOK struct {
	Payload *models.Alias
}

// IsSuccess returns true when this aliases create o k response has a 2xx status code
func (o *AliasesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this aliases create o k response has a 3xx status code
func (o *AliasesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aliases create o k response has a 4xx status code
func (o *AliasesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this aliases create o k response has a 5xx status code
func (o *AliasesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this aliases create o k response a status code equal to that given
func (o *AliasesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the aliases create o k response
func (o *AliasesCreateOK) Code() int {
	return 200
}

func (o *AliasesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Aliases][%d] aliasesCreateOK %s", 200, payload)
}

func (o *AliasesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Aliases][%d] aliasesCreateOK %s", 200, payload)
}

func (o *AliasesCreateOK) GetPayload() *models.Alias {
	return o.Payload
}

func (o *AliasesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Alias)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAliasesCreateDefault creates a AliasesCreateDefault with default headers values
func NewAliasesCreateDefault(code int) *AliasesCreateDefault {
	return &AliasesCreateDefault{
		_statusCode: code,
	}
}

/*
AliasesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type AliasesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this aliases create default response has a 2xx status code
func (o *AliasesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this aliases create default response has a 3xx status code
func (o *AliasesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this aliases create default response has a 4xx status code
func (o *AliasesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this aliases create default response has a 5xx status code
func (o *AliasesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this aliases create default response a status code equal to that given
func (o *AliasesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the aliases create default response
func (o *AliasesCreateDefault) Code() int {
	return o._statusCode
}

func (o *AliasesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Aliases][%d] Aliases_Create default %s", o._statusCode, payload)
}

func (o *AliasesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Aliases][%d] Aliases_Create default %s", o._statusCode, payload)
}

func (o *AliasesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AliasesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
