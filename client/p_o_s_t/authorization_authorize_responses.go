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

// AuthorizationAuthorizeReader is a Reader for the AuthorizationAuthorize structure.
type AuthorizationAuthorizeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AuthorizationAuthorizeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAuthorizationAuthorizeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAuthorizationAuthorizeDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAuthorizationAuthorizeOK creates a AuthorizationAuthorizeOK with default headers values
func NewAuthorizationAuthorizeOK() *AuthorizationAuthorizeOK {
	return &AuthorizationAuthorizeOK{}
}

/*
AuthorizationAuthorizeOK describes a response with status code 200, with default header values.

OK
*/
type AuthorizationAuthorizeOK struct {
	Payload *models.AuthorizationResponse
}

// IsSuccess returns true when this authorization authorize o k response has a 2xx status code
func (o *AuthorizationAuthorizeOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this authorization authorize o k response has a 3xx status code
func (o *AuthorizationAuthorizeOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this authorization authorize o k response has a 4xx status code
func (o *AuthorizationAuthorizeOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this authorization authorize o k response has a 5xx status code
func (o *AuthorizationAuthorizeOK) IsServerError() bool {
	return false
}

// IsCode returns true when this authorization authorize o k response a status code equal to that given
func (o *AuthorizationAuthorizeOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the authorization authorize o k response
func (o *AuthorizationAuthorizeOK) Code() int {
	return 200
}

func (o *AuthorizationAuthorizeOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /PaymentGateway/Authorization/Authorize][%d] authorizationAuthorizeOK %s", 200, payload)
}

func (o *AuthorizationAuthorizeOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /PaymentGateway/Authorization/Authorize][%d] authorizationAuthorizeOK %s", 200, payload)
}

func (o *AuthorizationAuthorizeOK) GetPayload() *models.AuthorizationResponse {
	return o.Payload
}

func (o *AuthorizationAuthorizeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AuthorizationResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAuthorizationAuthorizeDefault creates a AuthorizationAuthorizeDefault with default headers values
func NewAuthorizationAuthorizeDefault(code int) *AuthorizationAuthorizeDefault {
	return &AuthorizationAuthorizeDefault{
		_statusCode: code,
	}
}

/*
AuthorizationAuthorizeDefault describes a response with status code -1, with default header values.

Error
*/
type AuthorizationAuthorizeDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this authorization authorize default response has a 2xx status code
func (o *AuthorizationAuthorizeDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this authorization authorize default response has a 3xx status code
func (o *AuthorizationAuthorizeDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this authorization authorize default response has a 4xx status code
func (o *AuthorizationAuthorizeDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this authorization authorize default response has a 5xx status code
func (o *AuthorizationAuthorizeDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this authorization authorize default response a status code equal to that given
func (o *AuthorizationAuthorizeDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the authorization authorize default response
func (o *AuthorizationAuthorizeDefault) Code() int {
	return o._statusCode
}

func (o *AuthorizationAuthorizeDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /PaymentGateway/Authorization/Authorize][%d] Authorization_Authorize default %s", o._statusCode, payload)
}

func (o *AuthorizationAuthorizeDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /PaymentGateway/Authorization/Authorize][%d] Authorization_Authorize default %s", o._statusCode, payload)
}

func (o *AuthorizationAuthorizeDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AuthorizationAuthorizeDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}