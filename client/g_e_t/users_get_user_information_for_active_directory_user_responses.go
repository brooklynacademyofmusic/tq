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

// UsersGetUserInformationForActiveDirectoryUserReader is a Reader for the UsersGetUserInformationForActiveDirectoryUser structure.
type UsersGetUserInformationForActiveDirectoryUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UsersGetUserInformationForActiveDirectoryUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUsersGetUserInformationForActiveDirectoryUserOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewUsersGetUserInformationForActiveDirectoryUserDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewUsersGetUserInformationForActiveDirectoryUserOK creates a UsersGetUserInformationForActiveDirectoryUserOK with default headers values
func NewUsersGetUserInformationForActiveDirectoryUserOK() *UsersGetUserInformationForActiveDirectoryUserOK {
	return &UsersGetUserInformationForActiveDirectoryUserOK{}
}

/*
UsersGetUserInformationForActiveDirectoryUserOK describes a response with status code 200, with default header values.

OK
*/
type UsersGetUserInformationForActiveDirectoryUserOK struct {
	Payload *models.UserInformation
}

// IsSuccess returns true when this users get user information for active directory user o k response has a 2xx status code
func (o *UsersGetUserInformationForActiveDirectoryUserOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this users get user information for active directory user o k response has a 3xx status code
func (o *UsersGetUserInformationForActiveDirectoryUserOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this users get user information for active directory user o k response has a 4xx status code
func (o *UsersGetUserInformationForActiveDirectoryUserOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this users get user information for active directory user o k response has a 5xx status code
func (o *UsersGetUserInformationForActiveDirectoryUserOK) IsServerError() bool {
	return false
}

// IsCode returns true when this users get user information for active directory user o k response a status code equal to that given
func (o *UsersGetUserInformationForActiveDirectoryUserOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the users get user information for active directory user o k response
func (o *UsersGetUserInformationForActiveDirectoryUserOK) Code() int {
	return 200
}

func (o *UsersGetUserInformationForActiveDirectoryUserOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/Users/Info][%d] usersGetUserInformationForActiveDirectoryUserOK %s", 200, payload)
}

func (o *UsersGetUserInformationForActiveDirectoryUserOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/Users/Info][%d] usersGetUserInformationForActiveDirectoryUserOK %s", 200, payload)
}

func (o *UsersGetUserInformationForActiveDirectoryUserOK) GetPayload() *models.UserInformation {
	return o.Payload
}

func (o *UsersGetUserInformationForActiveDirectoryUserOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UserInformation)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUsersGetUserInformationForActiveDirectoryUserDefault creates a UsersGetUserInformationForActiveDirectoryUserDefault with default headers values
func NewUsersGetUserInformationForActiveDirectoryUserDefault(code int) *UsersGetUserInformationForActiveDirectoryUserDefault {
	return &UsersGetUserInformationForActiveDirectoryUserDefault{
		_statusCode: code,
	}
}

/*
UsersGetUserInformationForActiveDirectoryUserDefault describes a response with status code -1, with default header values.

Error
*/
type UsersGetUserInformationForActiveDirectoryUserDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this users get user information for active directory user default response has a 2xx status code
func (o *UsersGetUserInformationForActiveDirectoryUserDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this users get user information for active directory user default response has a 3xx status code
func (o *UsersGetUserInformationForActiveDirectoryUserDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this users get user information for active directory user default response has a 4xx status code
func (o *UsersGetUserInformationForActiveDirectoryUserDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this users get user information for active directory user default response has a 5xx status code
func (o *UsersGetUserInformationForActiveDirectoryUserDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this users get user information for active directory user default response a status code equal to that given
func (o *UsersGetUserInformationForActiveDirectoryUserDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the users get user information for active directory user default response
func (o *UsersGetUserInformationForActiveDirectoryUserDefault) Code() int {
	return o._statusCode
}

func (o *UsersGetUserInformationForActiveDirectoryUserDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/Users/Info][%d] Users_GetUserInformationForActiveDirectoryUser default %s", o._statusCode, payload)
}

func (o *UsersGetUserInformationForActiveDirectoryUserDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Security/Users/Info][%d] Users_GetUserInformationForActiveDirectoryUser default %s", o._statusCode, payload)
}

func (o *UsersGetUserInformationForActiveDirectoryUserDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *UsersGetUserInformationForActiveDirectoryUserDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
