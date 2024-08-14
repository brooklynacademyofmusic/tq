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

// KeywordsCreateReader is a Reader for the KeywordsCreate structure.
type KeywordsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *KeywordsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewKeywordsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewKeywordsCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewKeywordsCreateOK creates a KeywordsCreateOK with default headers values
func NewKeywordsCreateOK() *KeywordsCreateOK {
	return &KeywordsCreateOK{}
}

/*
KeywordsCreateOK describes a response with status code 200, with default header values.

OK
*/
type KeywordsCreateOK struct {
	Payload *models.Keyword
}

// IsSuccess returns true when this keywords create o k response has a 2xx status code
func (o *KeywordsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this keywords create o k response has a 3xx status code
func (o *KeywordsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this keywords create o k response has a 4xx status code
func (o *KeywordsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this keywords create o k response has a 5xx status code
func (o *KeywordsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this keywords create o k response a status code equal to that given
func (o *KeywordsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the keywords create o k response
func (o *KeywordsCreateOK) Code() int {
	return 200
}

func (o *KeywordsCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Keywords][%d] keywordsCreateOK %s", 200, payload)
}

func (o *KeywordsCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Keywords][%d] keywordsCreateOK %s", 200, payload)
}

func (o *KeywordsCreateOK) GetPayload() *models.Keyword {
	return o.Payload
}

func (o *KeywordsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Keyword)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewKeywordsCreateDefault creates a KeywordsCreateDefault with default headers values
func NewKeywordsCreateDefault(code int) *KeywordsCreateDefault {
	return &KeywordsCreateDefault{
		_statusCode: code,
	}
}

/*
KeywordsCreateDefault describes a response with status code -1, with default header values.

Error
*/
type KeywordsCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this keywords create default response has a 2xx status code
func (o *KeywordsCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this keywords create default response has a 3xx status code
func (o *KeywordsCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this keywords create default response has a 4xx status code
func (o *KeywordsCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this keywords create default response has a 5xx status code
func (o *KeywordsCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this keywords create default response a status code equal to that given
func (o *KeywordsCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the keywords create default response
func (o *KeywordsCreateDefault) Code() int {
	return o._statusCode
}

func (o *KeywordsCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Keywords][%d] Keywords_Create default %s", o._statusCode, payload)
}

func (o *KeywordsCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Keywords][%d] Keywords_Create default %s", o._statusCode, payload)
}

func (o *KeywordsCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *KeywordsCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}