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

// ConstituenciesCreateReader is a Reader for the ConstituenciesCreate structure.
type ConstituenciesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ConstituenciesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewConstituenciesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewConstituenciesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewConstituenciesCreateOK creates a ConstituenciesCreateOK with default headers values
func NewConstituenciesCreateOK() *ConstituenciesCreateOK {
	return &ConstituenciesCreateOK{}
}

/*
ConstituenciesCreateOK describes a response with status code 200, with default header values.

OK
*/
type ConstituenciesCreateOK struct {
	Payload *models.Constituency
}

// IsSuccess returns true when this constituencies create o k response has a 2xx status code
func (o *ConstituenciesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this constituencies create o k response has a 3xx status code
func (o *ConstituenciesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this constituencies create o k response has a 4xx status code
func (o *ConstituenciesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this constituencies create o k response has a 5xx status code
func (o *ConstituenciesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this constituencies create o k response a status code equal to that given
func (o *ConstituenciesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the constituencies create o k response
func (o *ConstituenciesCreateOK) Code() int {
	return 200
}

func (o *ConstituenciesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Constituencies][%d] constituenciesCreateOK %s", 200, payload)
}

func (o *ConstituenciesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Constituencies][%d] constituenciesCreateOK %s", 200, payload)
}

func (o *ConstituenciesCreateOK) GetPayload() *models.Constituency {
	return o.Payload
}

func (o *ConstituenciesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Constituency)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConstituenciesCreateDefault creates a ConstituenciesCreateDefault with default headers values
func NewConstituenciesCreateDefault(code int) *ConstituenciesCreateDefault {
	return &ConstituenciesCreateDefault{
		_statusCode: code,
	}
}

/*
ConstituenciesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type ConstituenciesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this constituencies create default response has a 2xx status code
func (o *ConstituenciesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this constituencies create default response has a 3xx status code
func (o *ConstituenciesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this constituencies create default response has a 4xx status code
func (o *ConstituenciesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this constituencies create default response has a 5xx status code
func (o *ConstituenciesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this constituencies create default response a status code equal to that given
func (o *ConstituenciesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the constituencies create default response
func (o *ConstituenciesCreateDefault) Code() int {
	return o._statusCode
}

func (o *ConstituenciesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Constituencies][%d] Constituencies_Create default %s", o._statusCode, payload)
}

func (o *ConstituenciesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Constituencies][%d] Constituencies_Create default %s", o._statusCode, payload)
}

func (o *ConstituenciesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ConstituenciesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}