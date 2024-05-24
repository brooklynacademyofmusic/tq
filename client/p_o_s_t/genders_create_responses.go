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

// GendersCreateReader is a Reader for the GendersCreate structure.
type GendersCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GendersCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGendersCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGendersCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGendersCreateOK creates a GendersCreateOK with default headers values
func NewGendersCreateOK() *GendersCreateOK {
	return &GendersCreateOK{}
}

/*
GendersCreateOK describes a response with status code 200, with default header values.

OK
*/
type GendersCreateOK struct {
	Payload *models.Gender
}

// IsSuccess returns true when this genders create o k response has a 2xx status code
func (o *GendersCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this genders create o k response has a 3xx status code
func (o *GendersCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this genders create o k response has a 4xx status code
func (o *GendersCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this genders create o k response has a 5xx status code
func (o *GendersCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this genders create o k response a status code equal to that given
func (o *GendersCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the genders create o k response
func (o *GendersCreateOK) Code() int {
	return 200
}

func (o *GendersCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Genders][%d] gendersCreateOK %s", 200, payload)
}

func (o *GendersCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Genders][%d] gendersCreateOK %s", 200, payload)
}

func (o *GendersCreateOK) GetPayload() *models.Gender {
	return o.Payload
}

func (o *GendersCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Gender)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGendersCreateDefault creates a GendersCreateDefault with default headers values
func NewGendersCreateDefault(code int) *GendersCreateDefault {
	return &GendersCreateDefault{
		_statusCode: code,
	}
}

/*
GendersCreateDefault describes a response with status code -1, with default header values.

Error
*/
type GendersCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this genders create default response has a 2xx status code
func (o *GendersCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this genders create default response has a 3xx status code
func (o *GendersCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this genders create default response has a 4xx status code
func (o *GendersCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this genders create default response has a 5xx status code
func (o *GendersCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this genders create default response a status code equal to that given
func (o *GendersCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the genders create default response
func (o *GendersCreateDefault) Code() int {
	return o._statusCode
}

func (o *GendersCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Genders][%d] Genders_Create default %s", o._statusCode, payload)
}

func (o *GendersCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/Genders][%d] Genders_Create default %s", o._statusCode, payload)
}

func (o *GendersCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *GendersCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
