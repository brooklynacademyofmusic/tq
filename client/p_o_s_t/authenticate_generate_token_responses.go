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

// AuthenticateGenerateTokenReader is a Reader for the AuthenticateGenerateToken structure.
type AuthenticateGenerateTokenReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AuthenticateGenerateTokenReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAuthenticateGenerateTokenOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAuthenticateGenerateTokenDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAuthenticateGenerateTokenOK creates a AuthenticateGenerateTokenOK with default headers values
func NewAuthenticateGenerateTokenOK() *AuthenticateGenerateTokenOK {
	return &AuthenticateGenerateTokenOK{}
}

/*
AuthenticateGenerateTokenOK describes a response with status code 200, with default header values.

OK
*/
type AuthenticateGenerateTokenOK struct {
	Payload *models.AuthenticationTokenResponse
}

// IsSuccess returns true when this authenticate generate token o k response has a 2xx status code
func (o *AuthenticateGenerateTokenOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this authenticate generate token o k response has a 3xx status code
func (o *AuthenticateGenerateTokenOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this authenticate generate token o k response has a 4xx status code
func (o *AuthenticateGenerateTokenOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this authenticate generate token o k response has a 5xx status code
func (o *AuthenticateGenerateTokenOK) IsServerError() bool {
	return false
}

// IsCode returns true when this authenticate generate token o k response a status code equal to that given
func (o *AuthenticateGenerateTokenOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the authenticate generate token o k response
func (o *AuthenticateGenerateTokenOK) Code() int {
	return 200
}

func (o *AuthenticateGenerateTokenOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Security/Authenticate/Token/Generate][%d] authenticateGenerateTokenOK %s", 200, payload)
}

func (o *AuthenticateGenerateTokenOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Security/Authenticate/Token/Generate][%d] authenticateGenerateTokenOK %s", 200, payload)
}

func (o *AuthenticateGenerateTokenOK) GetPayload() *models.AuthenticationTokenResponse {
	return o.Payload
}

func (o *AuthenticateGenerateTokenOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AuthenticationTokenResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAuthenticateGenerateTokenDefault creates a AuthenticateGenerateTokenDefault with default headers values
func NewAuthenticateGenerateTokenDefault(code int) *AuthenticateGenerateTokenDefault {
	return &AuthenticateGenerateTokenDefault{
		_statusCode: code,
	}
}

/*
AuthenticateGenerateTokenDefault describes a response with status code -1, with default header values.

Error
*/
type AuthenticateGenerateTokenDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this authenticate generate token default response has a 2xx status code
func (o *AuthenticateGenerateTokenDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this authenticate generate token default response has a 3xx status code
func (o *AuthenticateGenerateTokenDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this authenticate generate token default response has a 4xx status code
func (o *AuthenticateGenerateTokenDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this authenticate generate token default response has a 5xx status code
func (o *AuthenticateGenerateTokenDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this authenticate generate token default response a status code equal to that given
func (o *AuthenticateGenerateTokenDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the authenticate generate token default response
func (o *AuthenticateGenerateTokenDefault) Code() int {
	return o._statusCode
}

func (o *AuthenticateGenerateTokenDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Security/Authenticate/Token/Generate][%d] Authenticate_GenerateToken default %s", o._statusCode, payload)
}

func (o *AuthenticateGenerateTokenDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Security/Authenticate/Token/Generate][%d] Authenticate_GenerateToken default %s", o._statusCode, payload)
}

func (o *AuthenticateGenerateTokenDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AuthenticateGenerateTokenDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
