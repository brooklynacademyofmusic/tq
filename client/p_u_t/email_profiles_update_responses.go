// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

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

// EmailProfilesUpdateReader is a Reader for the EmailProfilesUpdate structure.
type EmailProfilesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *EmailProfilesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewEmailProfilesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewEmailProfilesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewEmailProfilesUpdateOK creates a EmailProfilesUpdateOK with default headers values
func NewEmailProfilesUpdateOK() *EmailProfilesUpdateOK {
	return &EmailProfilesUpdateOK{}
}

/*
EmailProfilesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type EmailProfilesUpdateOK struct {
	Payload *models.EmailProfile
}

// IsSuccess returns true when this email profiles update o k response has a 2xx status code
func (o *EmailProfilesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this email profiles update o k response has a 3xx status code
func (o *EmailProfilesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this email profiles update o k response has a 4xx status code
func (o *EmailProfilesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this email profiles update o k response has a 5xx status code
func (o *EmailProfilesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this email profiles update o k response a status code equal to that given
func (o *EmailProfilesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the email profiles update o k response
func (o *EmailProfilesUpdateOK) Code() int {
	return 200
}

func (o *EmailProfilesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/EmailProfiles/{id}][%d] emailProfilesUpdateOK %s", 200, payload)
}

func (o *EmailProfilesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/EmailProfiles/{id}][%d] emailProfilesUpdateOK %s", 200, payload)
}

func (o *EmailProfilesUpdateOK) GetPayload() *models.EmailProfile {
	return o.Payload
}

func (o *EmailProfilesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.EmailProfile)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEmailProfilesUpdateDefault creates a EmailProfilesUpdateDefault with default headers values
func NewEmailProfilesUpdateDefault(code int) *EmailProfilesUpdateDefault {
	return &EmailProfilesUpdateDefault{
		_statusCode: code,
	}
}

/*
EmailProfilesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type EmailProfilesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this email profiles update default response has a 2xx status code
func (o *EmailProfilesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this email profiles update default response has a 3xx status code
func (o *EmailProfilesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this email profiles update default response has a 4xx status code
func (o *EmailProfilesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this email profiles update default response has a 5xx status code
func (o *EmailProfilesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this email profiles update default response a status code equal to that given
func (o *EmailProfilesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the email profiles update default response
func (o *EmailProfilesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *EmailProfilesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/EmailProfiles/{id}][%d] EmailProfiles_Update default %s", o._statusCode, payload)
}

func (o *EmailProfilesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/EmailProfiles/{id}][%d] EmailProfiles_Update default %s", o._statusCode, payload)
}

func (o *EmailProfilesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *EmailProfilesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
