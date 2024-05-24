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

// PhoneIndicatorsCreateReader is a Reader for the PhoneIndicatorsCreate structure.
type PhoneIndicatorsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PhoneIndicatorsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPhoneIndicatorsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPhoneIndicatorsCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPhoneIndicatorsCreateOK creates a PhoneIndicatorsCreateOK with default headers values
func NewPhoneIndicatorsCreateOK() *PhoneIndicatorsCreateOK {
	return &PhoneIndicatorsCreateOK{}
}

/*
PhoneIndicatorsCreateOK describes a response with status code 200, with default header values.

OK
*/
type PhoneIndicatorsCreateOK struct {
	Payload *models.PhoneIndicator
}

// IsSuccess returns true when this phone indicators create o k response has a 2xx status code
func (o *PhoneIndicatorsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this phone indicators create o k response has a 3xx status code
func (o *PhoneIndicatorsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this phone indicators create o k response has a 4xx status code
func (o *PhoneIndicatorsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this phone indicators create o k response has a 5xx status code
func (o *PhoneIndicatorsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this phone indicators create o k response a status code equal to that given
func (o *PhoneIndicatorsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the phone indicators create o k response
func (o *PhoneIndicatorsCreateOK) Code() int {
	return 200
}

func (o *PhoneIndicatorsCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PhoneIndicators][%d] phoneIndicatorsCreateOK %s", 200, payload)
}

func (o *PhoneIndicatorsCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PhoneIndicators][%d] phoneIndicatorsCreateOK %s", 200, payload)
}

func (o *PhoneIndicatorsCreateOK) GetPayload() *models.PhoneIndicator {
	return o.Payload
}

func (o *PhoneIndicatorsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PhoneIndicator)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPhoneIndicatorsCreateDefault creates a PhoneIndicatorsCreateDefault with default headers values
func NewPhoneIndicatorsCreateDefault(code int) *PhoneIndicatorsCreateDefault {
	return &PhoneIndicatorsCreateDefault{
		_statusCode: code,
	}
}

/*
PhoneIndicatorsCreateDefault describes a response with status code -1, with default header values.

Error
*/
type PhoneIndicatorsCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this phone indicators create default response has a 2xx status code
func (o *PhoneIndicatorsCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this phone indicators create default response has a 3xx status code
func (o *PhoneIndicatorsCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this phone indicators create default response has a 4xx status code
func (o *PhoneIndicatorsCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this phone indicators create default response has a 5xx status code
func (o *PhoneIndicatorsCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this phone indicators create default response a status code equal to that given
func (o *PhoneIndicatorsCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the phone indicators create default response
func (o *PhoneIndicatorsCreateDefault) Code() int {
	return o._statusCode
}

func (o *PhoneIndicatorsCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PhoneIndicators][%d] PhoneIndicators_Create default %s", o._statusCode, payload)
}

func (o *PhoneIndicatorsCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/PhoneIndicators][%d] PhoneIndicators_Create default %s", o._statusCode, payload)
}

func (o *PhoneIndicatorsCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PhoneIndicatorsCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
