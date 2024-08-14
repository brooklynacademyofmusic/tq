// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

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

// EmailProfilesGetAllReader is a Reader for the EmailProfilesGetAll structure.
type EmailProfilesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *EmailProfilesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewEmailProfilesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewEmailProfilesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewEmailProfilesGetAllOK creates a EmailProfilesGetAllOK with default headers values
func NewEmailProfilesGetAllOK() *EmailProfilesGetAllOK {
	return &EmailProfilesGetAllOK{}
}

/*
EmailProfilesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type EmailProfilesGetAllOK struct {
	Payload []*models.EmailProfile
}

// IsSuccess returns true when this email profiles get all o k response has a 2xx status code
func (o *EmailProfilesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this email profiles get all o k response has a 3xx status code
func (o *EmailProfilesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this email profiles get all o k response has a 4xx status code
func (o *EmailProfilesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this email profiles get all o k response has a 5xx status code
func (o *EmailProfilesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this email profiles get all o k response a status code equal to that given
func (o *EmailProfilesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the email profiles get all o k response
func (o *EmailProfilesGetAllOK) Code() int {
	return 200
}

func (o *EmailProfilesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/EmailProfiles][%d] emailProfilesGetAllOK %s", 200, payload)
}

func (o *EmailProfilesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/EmailProfiles][%d] emailProfilesGetAllOK %s", 200, payload)
}

func (o *EmailProfilesGetAllOK) GetPayload() []*models.EmailProfile {
	return o.Payload
}

func (o *EmailProfilesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEmailProfilesGetAllDefault creates a EmailProfilesGetAllDefault with default headers values
func NewEmailProfilesGetAllDefault(code int) *EmailProfilesGetAllDefault {
	return &EmailProfilesGetAllDefault{
		_statusCode: code,
	}
}

/*
EmailProfilesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type EmailProfilesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this email profiles get all default response has a 2xx status code
func (o *EmailProfilesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this email profiles get all default response has a 3xx status code
func (o *EmailProfilesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this email profiles get all default response has a 4xx status code
func (o *EmailProfilesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this email profiles get all default response has a 5xx status code
func (o *EmailProfilesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this email profiles get all default response a status code equal to that given
func (o *EmailProfilesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the email profiles get all default response
func (o *EmailProfilesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *EmailProfilesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/EmailProfiles][%d] EmailProfiles_GetAll default %s", o._statusCode, payload)
}

func (o *EmailProfilesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/EmailProfiles][%d] EmailProfiles_GetAll default %s", o._statusCode, payload)
}

func (o *EmailProfilesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *EmailProfilesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}