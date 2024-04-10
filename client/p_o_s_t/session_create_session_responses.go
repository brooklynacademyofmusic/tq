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

// SessionCreateSessionReader is a Reader for the SessionCreateSession structure.
type SessionCreateSessionReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SessionCreateSessionReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSessionCreateSessionOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /Web/Session] Session_CreateSession", response, response.Code())
	}
}

// NewSessionCreateSessionOK creates a SessionCreateSessionOK with default headers values
func NewSessionCreateSessionOK() *SessionCreateSessionOK {
	return &SessionCreateSessionOK{}
}

/*
SessionCreateSessionOK describes a response with status code 200, with default header values.

OK
*/
type SessionCreateSessionOK struct {
	Payload *models.SessionResponse
}

// IsSuccess returns true when this session create session o k response has a 2xx status code
func (o *SessionCreateSessionOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this session create session o k response has a 3xx status code
func (o *SessionCreateSessionOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this session create session o k response has a 4xx status code
func (o *SessionCreateSessionOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this session create session o k response has a 5xx status code
func (o *SessionCreateSessionOK) IsServerError() bool {
	return false
}

// IsCode returns true when this session create session o k response a status code equal to that given
func (o *SessionCreateSessionOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the session create session o k response
func (o *SessionCreateSessionOK) Code() int {
	return 200
}

func (o *SessionCreateSessionOK) Error() string {
	return fmt.Sprintf("[POST /Web/Session][%d] sessionCreateSessionOK  %+v", 200, o.Payload)
}

func (o *SessionCreateSessionOK) String() string {
	return fmt.Sprintf("[POST /Web/Session][%d] sessionCreateSessionOK  %+v", 200, o.Payload)
}

func (o *SessionCreateSessionOK) GetPayload() *models.SessionResponse {
	return o.Payload
}

func (o *SessionCreateSessionOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SessionResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}