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

// UserPreferencesUpdateReader is a Reader for the UserPreferencesUpdate structure.
type UserPreferencesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UserPreferencesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUserPreferencesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewUserPreferencesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewUserPreferencesUpdateOK creates a UserPreferencesUpdateOK with default headers values
func NewUserPreferencesUpdateOK() *UserPreferencesUpdateOK {
	return &UserPreferencesUpdateOK{}
}

/*
UserPreferencesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type UserPreferencesUpdateOK struct {
	Payload *models.UserPreference
}

// IsSuccess returns true when this user preferences update o k response has a 2xx status code
func (o *UserPreferencesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this user preferences update o k response has a 3xx status code
func (o *UserPreferencesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this user preferences update o k response has a 4xx status code
func (o *UserPreferencesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this user preferences update o k response has a 5xx status code
func (o *UserPreferencesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this user preferences update o k response a status code equal to that given
func (o *UserPreferencesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the user preferences update o k response
func (o *UserPreferencesUpdateOK) Code() int {
	return 200
}

func (o *UserPreferencesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Security/UserPreferences/{id}][%d] userPreferencesUpdateOK %s", 200, payload)
}

func (o *UserPreferencesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Security/UserPreferences/{id}][%d] userPreferencesUpdateOK %s", 200, payload)
}

func (o *UserPreferencesUpdateOK) GetPayload() *models.UserPreference {
	return o.Payload
}

func (o *UserPreferencesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UserPreference)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUserPreferencesUpdateDefault creates a UserPreferencesUpdateDefault with default headers values
func NewUserPreferencesUpdateDefault(code int) *UserPreferencesUpdateDefault {
	return &UserPreferencesUpdateDefault{
		_statusCode: code,
	}
}

/*
UserPreferencesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type UserPreferencesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this user preferences update default response has a 2xx status code
func (o *UserPreferencesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this user preferences update default response has a 3xx status code
func (o *UserPreferencesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this user preferences update default response has a 4xx status code
func (o *UserPreferencesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this user preferences update default response has a 5xx status code
func (o *UserPreferencesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this user preferences update default response a status code equal to that given
func (o *UserPreferencesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the user preferences update default response
func (o *UserPreferencesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *UserPreferencesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Security/UserPreferences/{id}][%d] UserPreferences_Update default %s", o._statusCode, payload)
}

func (o *UserPreferencesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Security/UserPreferences/{id}][%d] UserPreferences_Update default %s", o._statusCode, payload)
}

func (o *UserPreferencesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *UserPreferencesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
