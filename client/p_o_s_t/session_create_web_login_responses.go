// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// SessionCreateWebLoginReader is a Reader for the SessionCreateWebLogin structure.
type SessionCreateWebLoginReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SessionCreateWebLoginReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSessionCreateWebLoginOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /Web/Session/{sessionKey}/WebLogins] Session_CreateWebLogin", response, response.Code())
	}
}

// NewSessionCreateWebLoginOK creates a SessionCreateWebLoginOK with default headers values
func NewSessionCreateWebLoginOK() *SessionCreateWebLoginOK {
	return &SessionCreateWebLoginOK{}
}

/*
SessionCreateWebLoginOK describes a response with status code 200, with default header values.

OK
*/
type SessionCreateWebLoginOK struct {
	Payload *models.Session
}

// IsSuccess returns true when this session create web login o k response has a 2xx status code
func (o *SessionCreateWebLoginOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this session create web login o k response has a 3xx status code
func (o *SessionCreateWebLoginOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this session create web login o k response has a 4xx status code
func (o *SessionCreateWebLoginOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this session create web login o k response has a 5xx status code
func (o *SessionCreateWebLoginOK) IsServerError() bool {
	return false
}

// IsCode returns true when this session create web login o k response a status code equal to that given
func (o *SessionCreateWebLoginOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the session create web login o k response
func (o *SessionCreateWebLoginOK) Code() int {
	return 200
}

func (o *SessionCreateWebLoginOK) Error() string {
	return fmt.Sprintf("[POST /Web/Session/{sessionKey}/WebLogins][%d] sessionCreateWebLoginOK  %+v", 200, o.Payload)
}

func (o *SessionCreateWebLoginOK) String() string {
	return fmt.Sprintf("[POST /Web/Session/{sessionKey}/WebLogins][%d] sessionCreateWebLoginOK  %+v", 200, o.Payload)
}

func (o *SessionCreateWebLoginOK) GetPayload() *models.Session {
	return o.Payload
}

func (o *SessionCreateWebLoginOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Session)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}